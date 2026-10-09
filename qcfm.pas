unit qcfm;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, Math, uMisc, Generics.Collections;

type
  TMultiHeaderFileV1 = packed record
    magic: array[0..3] of char;
    checksum: dword;
    version: dword;
    nheaders: dword;
    headersz: dword;
    datachecksum: dword;
    flags: dword;
    dummy: array[0..3] of char;
  end;

  TControlFileV1 = packed record
    magic: array[0..3] of char;
    checksum: dword;
    version: dword;
    nrecords: dword;
    blocksize: dword;
    device: dword;
    partition: dword;
    datachecksum: dword;
    flags: dword;
    dummy: array[0..3] of char;
  end;

  TRunRecordV1 = packed record
    offset: integer;
    Count: dword;
  end;

  TMultiHeaderFileV2 = packed record
    magic: array[0..3] of char;
    header_cksum: dword;
    version: dword;
    length: dword;
    nheaders: dword;
    headersz: dword;
    data_crc: dword;
  end;

  TControlFileV2 = packed record
    magic: array[0..3] of char;
    version: dword;
    length: dword;
    _type: dword;
    rrecOffset: dword;
    nrecords: dword;
    hwvOffset: dword;
    hwvNumEntries: dword;
    sigOffset: dword;
    sigSize: dword;
    blocksize: dword;
  end;

  TRunRecordV2 = packed record
    magic: array[0..3] of char;
    length: dword;
    offset: dword;
    Count: dword;
  end;

type
  TRRChunk = record
    Offset: int64;
    Count: integer;
  end;

  TMFCQChunk = record
    Offset: int64;
    Size: int64;
    Flags: dword;
    ChunkType: string;
    BlockCount: integer;
    BlockSize: integer;
    RR: array of TRRChunk;
  end;

  TMFCQChunkArray = array of TMFCQChunk;

  TMFCQChunkArrays = record
    V1: TMFCQChunkArray;
    V2: TMFCQChunkArray;
  end;

  TMFCQVersion = (mfcqUnknown, mfcqV1, mfcqV2, mfcqHybrid);

  TBlockMapItem = record
    VirtOffset: int64;
    PhysOffset: int64;
  end;

  { TMFCQChunkStream }
  TMFCQChunkStream = class(TStream)
  private
    FSourceStream: TStream;
    FChunk: TMFCQChunk;
    FPosition: int64;
    FVirtualSize: int64;
    FBaseOffset: int64;
    FOwnsSource: boolean;
    FVersion: TMFCQVersion;
    FBlockMap: array of TBlockMapItem;
    procedure BuildBlockMap;
  public
    constructor Create(ASourceStream: TStream; const AChunk: TMFCQChunk; AVersion: TMFCQVersion;
      AOwnsSource: boolean = False);
    destructor Destroy; override;

    function Read(var Buffer; Count: longint): longint; override;
    function Write(const Buffer; Count: longint): longint; override;
    function Seek(const Offset: int64; Origin: TSeekOrigin): int64; override;

    property ChunkInfo: TMFCQChunk read FChunk;
    property ContainerVersion: TMFCQVersion read FVersion;
  end;

  { TMFCQContainerStream }
  TMFCQContainerStream = class
  private
    FSourceStream: TStream;
    FChunks: TMFCQChunkArrays;
    FOwnsSource: boolean;
    FVersion: TMFCQVersion;
    function DetectVersion: TMFCQVersion;
    function GetChunkCountV1: integer;
    function GetChunkCountV2: integer;
    function GetTotalChunkCount: integer;
  public
    constructor Create(const AFileName: string); overload;
    constructor Create(ASourceStream: TStream; AOwnsSource: boolean = False); overload;
    destructor Destroy; override;

    function GetChunkStreamV1(Index: integer): TMFCQChunkStream;
    function GetChunkStreamV2(Index: integer): TMFCQChunkStream;
    function GetChunkStream(Index: integer): TMFCQChunkStream;

    property Chunks: TMFCQChunkArrays read FChunks;
    property Version: TMFCQVersion read FVersion;
    property ChunkCountV1: integer read GetChunkCountV1;
    property ChunkCountV2: integer read GetChunkCountV2;
    property TotalChunkCount: integer read GetTotalChunkCount;
  end;

  { TMFCQPackStream }
  TVirtualBlockMap = record
    VirtualOffset: int64;
    SourceFileIdx: integer;
    FileOffset: int64;
    BlockSize: integer;
  end;

  AVirtualBlockMap = array of TVirtualBlockMap;

  TFileStreamMap = specialize TObjectDictionary<integer, TFileStream>;

  TMFCQPackStream = class(TStream)
  private
    FHeaderStream: TMemoryStream;
    FFiles: array of string;
    FBlockMap: array of TVirtualBlockMap;
    FCurrentFileStreams: TFileStreamMap;
    FPosition: int64;
    FTotalSize: int64;
    FPayloadSize: int64;
    FBlockSize: integer;
    FCb: TProgressCallback;
    FSign: boolean;
    FSigFinalized: boolean;
    FCrcVal: dword;
    FSignatureBuffer: array[0..559] of byte;
    procedure BuildHeadersAndMap(const iFiles: TStringList; ver: integer; fast: boolean);
    function GetSourceStream(FileIdx: integer): TFileStream;
  protected
    function GetSize: int64; override;
  public
    constructor Create(const iFiles: TStringList; cb: TProgressCallback = nil;
      ver: integer = 2; fast: boolean = False; sign: boolean = False);
    destructor Destroy; override;

    function Read(var Buffer; Count: longint): longint; override;
    function Write(const Buffer; Count: longint): longint; override;
    function Seek(const Offset: int64; Origin: TSeekOrigin): int64; override;

    property Files: TStringArray read FFiles;
    property BlockMap: AVirtualBlockMap read FBlockMap;
    property IsSigned: boolean read FSign;
    property PayloadSize: int64 read FPayloadSize;
    property BlockSize: integer read FBlockSize;
  end;

function AnalyzeMFCQChunks(inFile: TStream): TMFCQChunkArrays;
function AnalyzeMFCQChunks(const FileName: string): TMFCQChunkArrays;
procedure Chunk2Stream(inFile: TStream; const chunk: TMFCQChunk; outFile: TStream;
  cb: TProgressCallback = nil; outFileName: string = '');

procedure unpackMFCQ(fileName: string; cb: TProgressCallback = nil; const OutDir: string = '');
procedure packMFCQ(oFile: string; const iFiles: TStringList; cb: TProgressCallback = nil;
  ver: integer = 2; fast: boolean = False; sign: boolean = False);
procedure _packMFCQ(outFile: TStream; const iFiles: TStringList; cb: TProgressCallback = nil;
  ver: integer = 2; fast: boolean = False; sign: boolean = False);

function Type2Ext(t: integer): string;
function Ext2Type(const t: string): integer;
function Size2Blocks(const FileName: string; bs: integer = $10000): integer;

const
  signature_data: array[0..559] of byte = (
    $51, $4E, $58, $48, $2D, $4F, $53, $2D, $31, $00, $00, $00, $00, $00, $00, $00,
    $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
    $51, $4E, $58, $48, $88, $00, $00, $00, $D1, $42, $E9, $27, $E7, $AB, $A7, $FD,
    $1D, $8B, $6A, $C6, $F1, $58, $A4, $46, $92, $DA, $24, $AB, $22, $F1, $EA, $DE,
    $06, $12, $A9, $05, $37, $46, $F3, $BE, $01, $39, $AF, $C7, $F4, $A1, $F7, $93,
    $AF, $B6, $14, $33, $7B, $69, $47, $C8, $BA, $D9, $0F, $9B, $9F, $FF, $7A, $D3,
    $05, $D4, $78, $F1, $6B, $E5, $1C, $81, $30, $00, $00, $00, $46, $A1, $6C, $1E,
    $52, $A3, $A7, $C0, $58, $68, $0D, $3E, $D6, $85, $E0, $5B, $09, $E3, $6D, $A9,
    $BF, $20, $0D, $3B, $52, $C6, $DF, $3A, $4F, $B9, $48, $76, $F1, $68, $CC, $5F,
    $F8, $A6, $CA, $CE, $F3, $E5, $19, $BB, $EF, $E6, $F8, $D9, $B0, $9A, $25, $2B,
    $F2, $FB, $04, $BF, $0C, $BF, $98, $9E, $15, $4D, $01, $08, $53, $01, $00, $00,
    $BC, $00, $00, $00, $01, $00, $01, $00, $FD, $0B, $A6, $B5, $51, $4E, $58, $4C,
    $2D, $4F, $53, $2D, $31, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
    $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $51, $4E, $58, $4C,
    $88, $00, $00, $00, $99, $C4, $EC, $AC, $02, $E1, $E2, $E2, $7E, $3B, $66, $9F,
    $62, $4A, $41, $05, $95, $B6, $75, $2E, $72, $8A, $38, $78, $03, $54, $C8, $6F,
    $80, $3A, $5F, $5F, $6F, $4D, $63, $AF, $08, $94, $B4, $5F, $3F, $28, $91, $B7,
    $CF, $6A, $6E, $95, $FE, $DA, $64, $36, $F4, $57, $60, $84, $CC, $3F, $26, $9B,
    $2F, $53, $7E, $70, $80, $00, $00, $00, $DA, $81, $84, $05, $E4, $FE, $84, $AD,
    $FE, $9A, $40, $C1, $BA, $BE, $0B, $C9, $A8, $FA, $B7, $23, $73, $E4, $52, $07,
    $3A, $22, $E3, $EE, $E1, $19, $CF, $27, $51, $AF, $8A, $94, $89, $85, $5F, $01,
    $EC, $D0, $75, $1D, $42, $E7, $39, $40, $DF, $CF, $41, $75, $81, $AF, $58, $11,
    $EF, $66, $F2, $C8, $48, $9D, $22, $92, $76, $00, $00, $00, $BC, $00, $00, $00,
    $01, $00, $01, $00, $0E, $1C, $B7, $C6, $51, $4E, $58, $2D, $4F, $53, $2D, $31,
    $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
    $00, $00, $00, $00, $00, $00, $00, $00, $51, $4E, $58, $00, $80, $00, $00, $00,
    $BB, $AA, $BF, $CE, $E4, $A0, $9D, $14, $9F, $DC, $B4, $CA, $DF, $35, $B7, $F3,
    $B5, $A2, $C1, $6C, $3A, $92, $00, $10, $F0, $B1, $7E, $3F, $F0, $23, $E2, $BA,
    $FD, $D7, $A8, $0D, $E7, $B5, $A3, $69, $5E, $72, $2D, $FF, $8B, $F7, $A7, $99,
    $74, $75, $64, $48, $6A, $2E, $62, $61, $C7, $F5, $55, $34, $41, $8F, $7A, $90,
    $A3, $05, $C6, $3E, $41, $47, $84, $D3, $51, $05, $46, $4C, $F9, $A0, $B9, $52,
    $1E, $1A, $21, $8B, $EE, $94, $16, $BB, $CA, $F3, $16, $AF, $E0, $22, $8E, $16,
    $62, $42, $5B, $81, $43, $7E, $B0, $6E, $F9, $FE, $E3, $98, $86, $DF, $8F, $25,
    $E0, $DA, $F5, $9C, $00, $D8, $74, $30, $0B, $01, $1D, $D8, $5F, $91, $8A, $9D,
    $B4, $00, $00, $00, $01, $00, $01, $00, $1F, $2D, $C8, $D7, $23, $98, $F2, $4D);

implementation

uses crc, StrUtils, FileUtil;

type
  TBlockRange = record
    BlockIndex: integer;
    Count: integer;
  end;

  TBlockRangeArray = array of TBlockRange;

const
  imageNVRAM = $03;
  imageUFS = $05;
  imageMBR = $06;
  imageSIG = $07;
  imageIFS = $08;
  imageRFS = $09;
  imageR_MBR = $0A;
  imageR_SIG = $0B;
  imageR_RFS = $0C;
  imageCalWork = $0F;
  imageCalBackup = $10;
  imageDMI = $11;
  imageDMI_MBR = $12;
  imageDMI_FSYS = $13;
  imageOS = $18;
  imageSIG2 = $89;
  imageR_SIG2 = $8C;
  imageDMI_SIG2 = $93;

  defaultBlockSize = $10000;

function Type2Ext(t: integer): string;
begin
  case t of
    imageNVRAM: Result := '.nvram';
    imageUFS: Result := '.ufs';
    imageMBR: Result := '.mbr';
    imageSIG: Result := '.sig';
    imageIFS: Result := '.ifs';
    imageRFS: Result := '.rcfs';
    imageR_MBR: Result := '.radio.mbr';
    imageR_SIG: Result := '.radio.sig';
    imageR_RFS: Result := '.radio.rcfs';
    imageSIG2: Result := '.sig2';
    imageR_SIG2: Result := '.radio.sig2';
    imageCalWork: Result := '.calwork';
    imageCalBackup: Result := '.calbackup';
    imageDMI: Result := '.dmi';
    imageDMI_MBR: Result := '.dmi.mbr';
    imageDMI_FSYS: Result := '.dmi.fsys';
    imageOS: Result := '.os';
    imageDMI_SIG2: Result := '.dmi.sig2';
    else
      Result := '.unk';
  end;
end;

function Ext2Type(const t: string): integer;
var
  ext: string;
begin
  ext := LowerCase(t);
  case ext of
    '.nvram': Result := imageNVRAM;
    '.ufs': Result := imageUFS;
    '.mbr': Result := imageMBR;
    '.sig': Result := imageSIG;
    '.ifs': Result := imageIFS;
    '.rcfs': Result := imageRFS;
    '.radio.mbr': Result := imageR_MBR;
    '.radio.sig': Result := imageR_SIG;
    '.radio.rcfs': Result := imageR_RFS;
    '.sig2': Result := imageSIG2;
    '.radio.sig2': Result := imageR_SIG2;
    '.calwork': Result := imageCalWork;
    '.calbackup': Result := imageCalBackup;
    '.dmi': Result := imageDMI;
    '.dmi.mbr': Result := imageDMI_MBR;
    '.dmi.fsys': Result := imageDMI_FSYS;
    '.os': Result := imageOS;
    '.dmi.sig2': Result := imageDMI_SIG2;
    else
      Result := 0;
  end;
end;

function Size2Blocks(const FileName: string; bs: integer = defaultBlockSize): integer;
var
  fs: int64;
begin
  fs := FileSize(FileName);
  if fs <= 0 then Exit(0);
  Result := fs div bs;
  if (fs mod bs) <> 0 then Inc(Result);
end;

function AnalyzeFileBlocks(const FileName: string; BlockSize: integer = 4096): TBlockRangeArray;
var
  F: TFileStream;
  Buf: TBytes;
  BlockIndex, RangeStart: int64;
  Count, Capacity, ResLen: integer;
  InRange: boolean;
  BytesRead: integer;

  procedure AddRange(StartIdx: int64; Cnt: integer);
  begin
    if ResLen >= Capacity then
    begin
      Inc(Capacity, 64);
      SetLength(Result, Capacity);
    end;
    Result[ResLen].BlockIndex := StartIdx;
    Result[ResLen].Count := Cnt;
    Inc(ResLen);
  end;

begin
  ResLen := 0;
  Capacity := 0;
  SetLength(Result, 0);

  F := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
  try
    SetLength(Buf, BlockSize);
    BlockIndex := 0;
    InRange := False;
    Count := 0;

    while F.Position < F.Size do
    begin
      BytesRead := F.Read(Buf[0], BlockSize);
      if BytesRead > 0 then
      begin
        if BytesRead < BlockSize then
          SetLength(Buf, BytesRead);

        if not IsFullFFBlock_Branchless(Buf, High(Buf)) then
        begin
          if not InRange then
          begin
            RangeStart := BlockIndex;
            Count := 1;
            InRange := True;
          end
          else
            Inc(Count);
        end;
      end;

      if (BytesRead < BlockSize) or IsFullFFBlock_Branchless(Buf, High(Buf)) then
      begin
        if InRange then
        begin
          AddRange(RangeStart, Count);
          InRange := False;
        end;
      end;

      if Length(Buf) <> BlockSize then
        SetLength(Buf, BlockSize);

      Inc(BlockIndex);
    end;

    if InRange then
      AddRange(RangeStart, Count);

    SetLength(Result, ResLen);
  finally
    F.Free;
  end;
end;

{ TMFCQPackStream }

constructor TMFCQPackStream.Create(const iFiles: TStringList; cb: TProgressCallback;
  ver: integer; fast: boolean; sign: boolean);
begin
  inherited Create;
  if not Assigned(iFiles) or (iFiles.Count = 0) then
    raise Exception.Create('No input files specified');

  FCb := cb;
  FSign := sign;
  FSigFinalized := False;
  FPosition := 0;
  FCrcVal := crc32(0, nil, 0);
  FBlockSize := defaultBlockSize;
  FHeaderStream := TMemoryStream.Create;
  FCurrentFileStreams := TFileStreamMap.Create([doOwnsValues]);

  BuildHeadersAndMap(iFiles, ver, fast);
end;

destructor TMFCQPackStream.Destroy;
begin
  SetLength(FBlockMap, 0);
  SetLength(FFiles, 0);
  FreeAndNil(FCurrentFileStreams);
  FreeAndNil(FHeaderStream);
  inherited Destroy;
end;

procedure TMFCQPackStream.BuildHeadersAndMap(const iFiles: TStringList; ver: integer; fast: boolean);
type
  TXRec = record
    cf1: TControlFileV1;
    cf2: TControlFileV2;
    arr1: array of TRunRecordV1;
    arr2: array of TRunRecordV2;
  end;

  function GetValue(n: integer): cardinal; inline;
  begin
    if n <= 3 then
      Result := 3
    else
      Result := 7 + ((n - 4) div 4) * 4;
  end;

var
  mhf1: TMultiHeaderFileV1;
  mhf2: TMultiHeaderFileV2;
  XRec: array of TXRec;
  XBRA: array of TBlockRangeArray;
  totalFiles, i, j, k, c: integer;
  tmps, params: TStringArray;
  fileName: string;
  Delta, flags, dataSize, totalSize, xPos: int64;
  curVirtOffset, blockIdx, blockOffset: int64;
  buf: TBytes;
  vMap: TVirtualBlockMap;
  mapCount, totalBlocksCount: integer;
begin
  totalFiles := iFiles.Count;
  SetLength(FFiles, totalFiles);
  SetLength(XRec, totalFiles);
  SetLength(XBRA, totalFiles);

  FillChar(mhf1, SizeOf(mhf1), 0);
  mhf1.magic := 'mfcq';
  mhf1.version := 1;
  mhf1.nheaders := totalFiles;
  mhf1.flags := IfThen(ver > 1, SizeOf(TMultiHeaderFileV1), 0);

  totalBlocksCount := 0;

  for i := 0 to totalFiles - 1 do
  begin
    tmps := SplitString(iFiles[i], '=');
    fileName := ExpandFileName(tmps[0]);
    FFiles[i] := fileName;

    if not FileExists(fileName) then
      raise Exception.CreateFmt('Input file not found: %s', [fileName]);

    Delta := 0;
    flags := 0;

    if Length(tmps) > 1 then
    begin
      params := SplitString(tmps[1], ',');
      if Length(params) > 0 then
        Delta := StrToIntDef(params[0], 0);
      if Length(params) > 1 then
        flags := StrToIntDef(params[1], 0)
      else
        flags := IfThen((Length(fileName) > 0) and (fileName[Length(fileName)] = '!'), 2, 0);
    end;

    if fast then
    begin
      SetLength(XBRA[i], 1);
      XBRA[i][0].BlockIndex := 0;
      XBRA[i][0].Count := Size2Blocks(fileName, FBlockSize);
    end
    else
      XBRA[i] := AnalyzeFileBlocks(fileName, FBlockSize);

    c := Length(XBRA[i]);

    for j := 0 to c - 1 do
      Inc(totalBlocksCount, XBRA[i][j].Count);

    with XRec[i] do
    begin
      if (ver and 1) = 1 then
      begin
        FillChar(cf1, SizeOf(cf1), 0);
        cf1.magic := 'qcfp';
        cf1.version := 1;
        cf1.blocksize := FBlockSize;
        cf1.device := 0;
        cf1.flags := flags;
        cf1.partition := 0;
        cf1.nrecords := GetValue(c);
        SetLength(arr1, cf1.nrecords);
        if cf1.nrecords > 0 then
          FillChar(arr1[0], Length(arr1) * SizeOf(TRunRecordV1), 0);

        for j := 0 to c - 1 do
        begin
          arr1[j].offset := Delta + XBRA[i][j].BlockIndex;
          arr1[j].Count := XBRA[i][j].Count;
        end;
      end;

      if (ver and 2) = 2 then
      begin
        FillChar(cf2, SizeOf(cf2), 0);
        cf2.magic := 'pfcq';
        cf2.version := $20000;
        cf2.blocksize := FBlockSize;
        cf2.rrecOffset := SizeOf(TControlFileV2);
        cf2.nrecords := c;
        cf2.length := SizeOf(TControlFileV2) + c * SizeOf(TRunRecordV2);
        cf2._type := Ext2Type(ExtractFileExt(fileName));

        SetLength(arr2, c);
        for j := 0 to c - 1 do
        begin
          FillChar(arr2[j], SizeOf(TRunRecordV2), 0);
          arr2[j].magic := 'rrcq';
          arr2[j].length := SizeOf(TRunRecordV2);
          arr2[j].Count := XBRA[i][j].Count;
          arr2[j].offset := XBRA[i][j].BlockIndex;
        end;

        Inc(mhf1.flags, SizeOf(TControlFileV1) + cf1.nrecords * SizeOf(TRunRecordV1));
      end;
    end;
  end;

  if ver > 1 then
  begin
    FillChar(mhf2, SizeOf(mhf2), 0);
    mhf2.magic := 'mfcq';
    mhf2.version := $20000;
    mhf2.length := SizeOf(TMultiHeaderFileV2);
    mhf2.nheaders := totalFiles;
    if ver = 2 then
    begin
      mhf2.headersz := SizeOf(TMultiHeaderFileV1) + mhf2.length + mhf2.nheaders *
        (SizeOf(TControlFileV2) + SizeOf(TRunRecordV2));
      mhf1.nheaders := 0;
    end
    else
      mhf2.headersz := $10000;
    mhf1.headersz := mhf2.headersz + $20;
  end
  else
    mhf1.headersz := $10000;

  FHeaderStream.Clear;
  FHeaderStream.Position := SizeOf(mhf1);

  if (ver and 1) = 1 then
  begin
    for i := 0 to totalFiles - 1 do
    begin
      with XRec[i] do
      begin
        c := cf1.nrecords;
        dataSize := c * SizeOf(TRunRecordV1);
        totalSize := SizeOf(TControlFileV1) + dataSize;

        if c > 0 then
          cf1.datachecksum := crc32(0, @arr1[0], dataSize)
        else
          cf1.datachecksum := 0;

        cf1.checksum := 0;
        if Length(buf) < totalSize then
          SetLength(buf, totalSize);

        Move(cf1, buf[0], SizeOf(TControlFileV1));
        if dataSize > 0 then
          Move(arr1[0], buf[SizeOf(TControlFileV1)], dataSize);

        cf1.checksum := crc32(0, @buf[8], totalSize - 8);
        Move(cf1, buf[0], SizeOf(TControlFileV1));
        FHeaderStream.WriteBuffer(buf[0], totalSize);
      end;
    end;
  end;

  xPos := FHeaderStream.Position;
  mhf1.flags := xPos;

  FHeaderStream.Position := 0;
  FHeaderStream.WriteBuffer(mhf1, SizeOf(mhf1));
  FHeaderStream.Position := xPos;

  if (ver and 2) = 2 then
  begin
    FHeaderStream.WriteBuffer(mhf2, SizeOf(TMultiHeaderFileV2));
    for i := 0 to totalFiles - 1 do
    begin
      with XRec[i] do
      begin
        FHeaderStream.WriteBuffer(cf2, SizeOf(TControlFileV2));
        if cf2.nrecords > 0 then
          FHeaderStream.WriteBuffer(arr2[0], cf2.nrecords * SizeOf(TRunRecordV2));
      end;
    end;
  end;

  if FHeaderStream.Size < mhf1.headersz then
  begin
    FHeaderStream.Position := FHeaderStream.Size;
    FHeaderStream.SetSize(mhf1.headersz);
  end;

  curVirtOffset := mhf1.headersz;
  mapCount := 0;
  SetLength(FBlockMap, totalBlocksCount);

  for i := 0 to totalFiles - 1 do
  begin
    for j := 0 to High(XBRA[i]) do
    begin
      for k := 0 to XBRA[i][j].Count - 1 do
      begin
        blockIdx := XBRA[i][j].BlockIndex + k;
        blockOffset := blockIdx * FBlockSize;

        vMap.VirtualOffset := curVirtOffset;
        vMap.SourceFileIdx := i;
        vMap.FileOffset := blockOffset;
        vMap.BlockSize := FBlockSize;

        FBlockMap[mapCount] := vMap;
        Inc(mapCount);

        Inc(curVirtOffset, FBlockSize);
      end;
    end;
  end;

  FPayloadSize := curVirtOffset;

  if FSign then
  begin
    Move(signature_data[0], FSignatureBuffer[0], SizeOf(signature_data));
    FTotalSize := FPayloadSize + SizeOf(FSignatureBuffer);
  end
  else
    FTotalSize := FPayloadSize;
end;

function TMFCQPackStream.GetSourceStream(FileIdx: integer): TFileStream;
begin
  if not FCurrentFileStreams.TryGetValue(FileIdx, Result) then
  begin
    Result := TFileStream.Create(FFiles[FileIdx], fmOpenRead or fmShareDenyNone);
    FCurrentFileStreams.Add(FileIdx, Result);
  end;
end;

function TMFCQPackStream.GetSize: int64;
begin
  Result := FTotalSize;
end;

function TMFCQPackStream.Seek(const Offset: int64; Origin: TSeekOrigin): int64;
begin
  case Origin of
    soBeginning: FPosition := Offset;
    soCurrent: Inc(FPosition, Offset);
    soEnd: FPosition := FTotalSize + Offset;
  end;

  if FPosition < 0 then FPosition := 0;
  if FPosition > FTotalSize then FPosition := FTotalSize;

  Result := FPosition;
end;

function TMFCQPackStream.Read(var Buffer; Count: longint): longint;
var
  totalToRead, bytesRead, chunkSize: longint;
  bufPtr: pbyte;
  curPos, relOffset: int64;
  i: integer;
  srcStream: TFileStream;
  fileSize, bytesToReadFromFile: int64;
  sigOffset: int64;
  payloadBytesRead: longint;
begin
  if (Count <= 0) or (FPosition >= FTotalSize) then
    Exit(0);

  totalToRead := Min(Count, FTotalSize - FPosition);
  bytesRead := 0;
  bufPtr := @Buffer;
  curPos := FPosition;

  // 1. Читання заголовочної частини
  if curPos < FHeaderStream.Size then
  begin
    chunkSize := Min(totalToRead, FHeaderStream.Size - curPos);
    FHeaderStream.Position := curPos;
    FHeaderStream.ReadBuffer(bufPtr^, chunkSize);

    Inc(bytesRead, chunkSize);
    Inc(curPos, chunkSize);
    Inc(bufPtr, chunkSize);
  end;

  // 2. Читання пейлоаду за картою блоків
  if (bytesRead < totalToRead) and (curPos >= FHeaderStream.Size) and (curPos < FPayloadSize) then
  begin
    for i := 0 to High(FBlockMap) do
    begin
      if (curPos >= FBlockMap[i].VirtualOffset) and (curPos < FBlockMap[i].VirtualOffset +
        FBlockMap[i].BlockSize) then
      begin
        relOffset := curPos - FBlockMap[i].VirtualOffset;
        chunkSize := Min(totalToRead - bytesRead, FBlockMap[i].BlockSize - relOffset);

        FillChar(bufPtr^, chunkSize, 0);

        srcStream := GetSourceStream(FBlockMap[i].SourceFileIdx);
        fileSize := srcStream.Size;

        if FBlockMap[i].FileOffset + relOffset < fileSize then
        begin
          bytesToReadFromFile := Min(chunkSize, fileSize - (FBlockMap[i].FileOffset + relOffset));
          if bytesToReadFromFile > 0 then
          begin
            srcStream.Position := FBlockMap[i].FileOffset + relOffset;
            srcStream.ReadBuffer(bufPtr^, bytesToReadFromFile);
          end;
        end;

        Inc(bytesRead, chunkSize);
        Inc(curPos, chunkSize);
        Inc(bufPtr, chunkSize);

        if bytesRead >= totalToRead then Break;
      end;
    end;
  end;

  // Оновлення накопичувального CRC32 лише для байтів пейлоаду (хедера + файлів)
  if FSign and (bytesRead > 0) and (FPosition < FPayloadSize) then
  begin
    if FPosition + bytesRead <= FPayloadSize then
      payloadBytesRead := bytesRead
    else
      payloadBytesRead := FPayloadSize - FPosition;

    if payloadBytesRead > 0 then
      FCrcVal := crc32(FCrcVal, @Buffer, payloadBytesRead);
  end;

  // 3. Читання сигнатури та її фінальний розрахунок
  if FSign and (curPos >= FPayloadSize) and (curPos < FTotalSize) then
  begin
    // Записуємо CRC в кінець сигнатури перед першою вичіткою будь-якого байта сигнатури
    if not FSigFinalized then
    begin
      FCrcVal := crc32(FCrcVal, @FSignatureBuffer[0], SizeOf(FSignatureBuffer) - 4);
      Move(FCrcVal, FSignatureBuffer[SizeOf(FSignatureBuffer) - 4], SizeOf(dword));
      FSigFinalized := True;
    end;

    if bytesRead < totalToRead then
    begin
      sigOffset := curPos - FPayloadSize;
      chunkSize := Min(totalToRead - bytesRead, SizeOf(FSignatureBuffer) - sigOffset);
      if chunkSize > 0 then
      begin
        Move(FSignatureBuffer[sigOffset], bufPtr^, chunkSize);
        Inc(bytesRead, chunkSize);
        Inc(curPos, chunkSize);
      end;
    end;
  end;

  FPosition := curPos;
  Result := bytesRead;
end;

function TMFCQPackStream.Write(const Buffer; Count: longint): longint;
begin
  raise EStreamError.Create('TMFCQPackStream is read-only');
end;


{ TMFCQChunkStream }

constructor TMFCQChunkStream.Create(ASourceStream: TStream; const AChunk: TMFCQChunk;
  AVersion: TMFCQVersion; AOwnsSource: boolean);
begin
  inherited Create;
  FSourceStream := ASourceStream;
  FChunk := AChunk;
  FVersion := AVersion;
  FOwnsSource := AOwnsSource;
  FPosition := 0;

  if Length(FChunk.RR) > 0 then
    FBaseOffset := FChunk.RR[0].Offset
  else
    FBaseOffset := 0;

  BuildBlockMap;
end;

destructor TMFCQChunkStream.Destroy;
begin
  SetLength(FBlockMap, 0);
  if FOwnsSource then
    FreeAndNil(FSourceStream);
  inherited Destroy;
end;

procedure TMFCQChunkStream.BuildBlockMap;
var
  i, j, MapIdx: integer;
  CurrPhysOffset: int64;
  LastRR: TRRChunk;
begin
  if FChunk.BlockCount <= 0 then
  begin
    FVirtualSize := 0;
    Exit;
  end;

  SetLength(FBlockMap, FChunk.BlockCount);
  CurrPhysOffset := FChunk.Offset;
  MapIdx := 0;

  for i := 0 to High(FChunk.RR) do
  begin
    for j := 0 to FChunk.RR[i].Count - 1 do
    begin
      FBlockMap[MapIdx].VirtOffset := int64(FChunk.BlockSize) * ((FChunk.RR[i].Offset + j) - FBaseOffset);
      FBlockMap[MapIdx].PhysOffset := CurrPhysOffset;
      Inc(CurrPhysOffset, FChunk.BlockSize);
      Inc(MapIdx);
    end;
  end;

  LastRR := FChunk.RR[High(FChunk.RR)];
  FVirtualSize := int64(FChunk.BlockSize) * ((LastRR.Offset + LastRR.Count) - FBaseOffset);
end;

function TMFCQChunkStream.Read(var Buffer; Count: longint): longint;
var
  BytesToRead, BytesRead, TotalRead: longint;
  BufPtr: pbyte;
  i: integer;
  VirtStart, VirtEnd, PhysPos: int64;
  ChunkOffset, ReadChunkSize: longint;
begin
  if (FPosition >= FVirtualSize) or (Count <= 0) then
    Exit(0);

  TotalRead := 0;
  BytesToRead := Count;
  if FPosition + BytesToRead > FVirtualSize then
    BytesToRead := FVirtualSize - FPosition;

  BufPtr := @Buffer;

  for i := 0 to High(FBlockMap) do
  begin
    VirtStart := FBlockMap[i].VirtOffset;
    VirtEnd := VirtStart + FChunk.BlockSize;

    if (FPosition < VirtEnd) and ((FPosition + BytesToRead) > VirtStart) then
    begin
      if (FPosition + TotalRead) < VirtStart then
      begin
        ReadChunkSize := Min(VirtStart - (FPosition + TotalRead), BytesToRead - TotalRead);
        FillChar(BufPtr^, ReadChunkSize, $FF);
        Inc(TotalRead, ReadChunkSize);
        Inc(BufPtr, ReadChunkSize);
        if TotalRead >= BytesToRead then Break;
      end;

      ChunkOffset := (FPosition + TotalRead) - VirtStart;
      PhysPos := FBlockMap[i].PhysOffset + ChunkOffset;
      ReadChunkSize := Min(FChunk.BlockSize - ChunkOffset, BytesToRead - TotalRead);

      FSourceStream.Position := PhysPos;
      BytesRead := FSourceStream.Read(BufPtr^, ReadChunkSize);

      Inc(TotalRead, BytesRead);
      Inc(BufPtr, BytesRead);

      if TotalRead >= BytesToRead then Break;
    end;
  end;

  if TotalRead < BytesToRead then
  begin
    ReadChunkSize := BytesToRead - TotalRead;
    FillChar(BufPtr^, ReadChunkSize, $FF);
    Inc(TotalRead, ReadChunkSize);
  end;

  Inc(FPosition, TotalRead);
  Result := TotalRead;
end;

function TMFCQChunkStream.Write(const Buffer; Count: longint): longint;
begin
  raise EStreamError.Create('TMFCQChunkStream is read-only');
end;

function TMFCQChunkStream.Seek(const Offset: int64; Origin: TSeekOrigin): int64;
begin
  case Origin of
    soBeginning: FPosition := Offset;
    soCurrent: Inc(FPosition, Offset);
    soEnd: FPosition := FVirtualSize + Offset;
  end;

  if FPosition < 0 then FPosition := 0;
  if FPosition > FVirtualSize then FPosition := FVirtualSize;

  Result := FPosition;
end;

{ TMFCQContainerStream }

constructor TMFCQContainerStream.Create(const AFileName: string);
begin
  Create(TFileStream.Create(AFileName, fmOpenRead or fmShareDenyNone), True);
end;

constructor TMFCQContainerStream.Create(ASourceStream: TStream; AOwnsSource: boolean);
begin
  inherited Create;
  FSourceStream := ASourceStream;
  FOwnsSource := AOwnsSource;
  FChunks := AnalyzeMFCQChunks(FSourceStream);
  FVersion := DetectVersion;
end;

destructor TMFCQContainerStream.Destroy;
begin
  if FOwnsSource then
    FreeAndNil(FSourceStream);
  inherited Destroy;
end;

function TMFCQContainerStream.DetectVersion: TMFCQVersion;
var
  HasV1, HasV2: boolean;
begin
  HasV1 := Length(FChunks.V1) > 0;
  HasV2 := Length(FChunks.V2) > 0;

  if HasV1 and HasV2 then
    Result := mfcqHybrid
  else if HasV2 then
    Result := mfcqV2
  else if HasV1 then
    Result := mfcqV1
  else
    Result := mfcqUnknown;
end;

function TMFCQContainerStream.GetChunkCountV1: integer;
begin
  Result := Length(FChunks.V1);
end;

function TMFCQContainerStream.GetChunkCountV2: integer;
begin
  Result := Length(FChunks.V2);
end;

function TMFCQContainerStream.GetTotalChunkCount: integer;
begin
  if FVersion = mfcqV2 then
    Result := GetChunkCountV2
  else if FVersion = mfcqV1 then
    Result := GetChunkCountV1
  else
    Result := Max(GetChunkCountV1, GetChunkCountV2);
end;

function TMFCQContainerStream.GetChunkStreamV1(Index: integer): TMFCQChunkStream;
begin
  if (Index < 0) or (Index >= Length(FChunks.V1)) then
    raise EListError.CreateFmt('V1 Chunk Index %d out of bounds', [Index]);
  Result := TMFCQChunkStream.Create(FSourceStream, FChunks.V1[Index], mfcqV1, False);
end;

function TMFCQContainerStream.GetChunkStreamV2(Index: integer): TMFCQChunkStream;
begin
  if (Index < 0) or (Index >= Length(FChunks.V2)) then
    raise EListError.CreateFmt('V2 Chunk Index %d out of bounds', [Index]);
  Result := TMFCQChunkStream.Create(FSourceStream, FChunks.V2[Index], mfcqV2, False);
end;

function TMFCQContainerStream.GetChunkStream(Index: integer): TMFCQChunkStream;
begin
  if Length(FChunks.V2) > 0 then
    Result := GetChunkStreamV2(Index)
  else
    Result := GetChunkStreamV1(Index);
end;

procedure _packMFCQ(outFile: TStream; const iFiles: TStringList; cb: TProgressCallback = nil;
  ver: integer = 2; fast: boolean = False; sign: boolean = False);
var
  packStream: TMFCQPackStream;
  buffer: array[0..$FFFF] of byte; // Буфер 64 КБ ($10000)
  bytesRead, i, activeFileIdx, lastFileIdx: integer;
  curVirtPos, totalBlocks, currentBlock: int64;
  fn: string;
begin
  packStream := TMFCQPackStream.Create(iFiles, cb, ver, fast, sign);
  try
    lastFileIdx := -1;

    // Ініціалізація прогресу для першого файлу
    if Assigned(cb) and (Length(packStream.Files) > 0) then
    begin
      fn := packStream.Files[0];
      totalBlocks := Size2Blocks(fn, packStream.BlockSize);
      cb(fn, -1, totalBlocks);
      lastFileIdx := 0;
    end;

    repeat
      curVirtPos := packStream.Position;
      bytesRead := packStream.Read(buffer[0], SizeOf(buffer));

      if bytesRead > 0 then
      begin
        outFile.WriteBuffer(buffer[0], bytesRead);

        // Відображення прогресу
        if Assigned(cb) and (Length(packStream.BlockMap) > 0) then
        begin
          activeFileIdx := -1;
          for i := High(packStream.BlockMap) downto 0 do
          begin
            if curVirtPos >= packStream.BlockMap[i].VirtualOffset then
            begin
              activeFileIdx := packStream.BlockMap[i].SourceFileIdx;
              currentBlock := (packStream.BlockMap[i].FileOffset div packStream.BlockSize) + 1;
              Break;
            end;
          end;

          if (activeFileIdx >= 0) and (activeFileIdx < Length(packStream.Files)) then
          begin
            fn := packStream.Files[activeFileIdx];
            totalBlocks := Size2Blocks(fn, packStream.BlockSize);

            if activeFileIdx <> lastFileIdx then
            begin
              if lastFileIdx >= 0 then
                cb(packStream.Files[lastFileIdx], Size2Blocks(packStream.Files[lastFileIdx],
                  packStream.BlockSize), Size2Blocks(packStream.Files[lastFileIdx], packStream.BlockSize));

              cb(fn, -1, totalBlocks);
              lastFileIdx := activeFileIdx;
            end;

            cb(fn, currentBlock, totalBlocks);
          end;
        end;
      end;
    until bytesRead = 0;

    // Фінальний сигнал завершення для останнього файла
    if Assigned(cb) and (lastFileIdx >= 0) and (lastFileIdx < Length(packStream.Files)) then
    begin
      fn := packStream.Files[lastFileIdx];
      totalBlocks := Size2Blocks(fn, packStream.BlockSize);
      cb(fn, totalBlocks, totalBlocks);
    end;

  finally
    packStream.Free;
  end;
end;

procedure packMFCQ(oFile: string; const iFiles: TStringList; cb: TProgressCallback = nil;
  ver: integer = 2; fast: boolean = False; sign: boolean = False);
var
  outFile: TFileStream;
begin
  if oFile = '' then
    raise Exception.Create('Output file name cannot be empty');

  outFile := TFileStream.Create(ExpandFileName(oFile), fmCreate);
  try
    _packMFCQ(outFile, iFiles, cb, ver, fast, sign);
  finally
    FreeAndNil(outFile);
  end;
end;

type
  TRR = array of TRRChunk;

function AnalyzeMFCQChunks(inFile: TStream): TMFCQChunkArrays;
var
  mhf1: TMultiHeaderFileV1;
  mhf2: TMultiHeaderFileV2;
  cf1: TControlFileV1;
  cf2: TControlFileV2;
  rr1: TRunRecordV1;
  rr2: TRunRecordV2;
  i, bs: integer;
  payloadOff, fileSize: int64;
  isV2Present, isV1Present: boolean;
  v1Count, v2Count: integer;
  ResultV1, ResultV2: TMFCQChunkArray;

  procedure Validate(required: int64; const msg: string);
  begin
    if inFile.Position + required > fileSize then
      raise Exception.Create(msg);
  end;

  procedure ReadRunRecords(n: integer; bs: integer; var RR: TRR; useV2: boolean;
  var blkCount: integer; var payloadSize: int64);
  var
    k, realCount: integer;
    tmpRR: array of TRRChunk;
  begin
    payloadSize := 0;
    blkCount := 0;
    realCount := 0;
    SetLength(tmpRR, n);

    for k := 0 to n - 1 do
    begin
      if useV2 then
      begin
        Validate(SizeOf(rr2), 'Truncated - V2 run record');
        inFile.ReadBuffer(rr2, SizeOf(rr2));
        if rr2.magic <> 'rrcq' then
          raise Exception.Create('Invalid V2 run record magic');
        tmpRR[realCount].Count := rr2.Count;
        tmpRR[realCount].Offset := rr2.offset;
        Inc(realCount);
        Inc(blkCount, rr2.Count);
        Inc(payloadSize, int64(rr2.Count) * bs);
      end
      else
      begin
        Validate(SizeOf(rr1), 'Truncated - V1 run record');
        inFile.ReadBuffer(rr1, SizeOf(rr1));
        if (rr1.Count = 0) and (rr1.Offset = 0) then
          Continue;
        tmpRR[realCount].Count := rr1.Count;
        tmpRR[realCount].Offset := rr1.Offset;
        Inc(realCount);
        Inc(blkCount, rr1.Count);
        Inc(payloadSize, int64(rr1.Count) * bs);
      end;
    end;

    SetLength(RR, realCount);
    if realCount > 0 then
      Move(tmpRR[0], RR[0], realCount * SizeOf(TRRChunk));

    Inc(payloadOff, payloadSize);
  end;

begin
  fileSize := inFile.Size;
  if fileSize < SizeOf(mhf1) then
    raise Exception.Create('File too small');

  inFile.Position := 0;
  inFile.ReadBuffer(mhf1, SizeOf(mhf1));
  if mhf1.magic <> 'mfcq' then raise Exception.Create('Bad magic');

  if mhf1.flags <> 0 then
  begin
    inFile.Position := mhf1.flags;
    Validate(SizeOf(mhf2), 'Truncated V2 header');
    inFile.ReadBuffer(mhf2, SizeOf(mhf2));
    isV2Present := (mhf2.magic = 'mfcq');
    isV1Present := (mhf1.flags <> 32);
  end
  else
  begin
    isV1Present := True;
    isV2Present := False;
  end;

  v1Count := mhf1.nheaders;
  v2Count := IfThen(isV2Present, mhf2.nheaders, 0);

  SetLength(ResultV1, v1Count);
  SetLength(ResultV2, v2Count);

  if isV1Present then
  begin
    payloadOff := mhf1.headersz;
    inFile.Position := $20;
    for i := 0 to v1Count - 1 do
    begin
      Validate(SizeOf(cf1), 'Truncated V1 control');
      inFile.ReadBuffer(cf1, SizeOf(cf1));
      if (cf1.magic <> 'qcfp') or (cf1.version <> 1) then
        raise Exception.Create('Invalid V1 control file');

      bs := IfThen(cf1.blocksize > 0, cf1.blocksize, defaultBlockSize);

      with ResultV1[i] do
      begin
        Offset := payloadOff;
        ChunkType := Format('.unk_%d', [i]);
        BlockSize := bs;
        Flags := cf1.flags;
        ReadRunRecords(cf1.nrecords, bs, RR, False, BlockCount, Size);
      end;
    end;
  end;

  if isV2Present then
  begin
    payloadOff := mhf1.headersz;
    inFile.Position := mhf1.flags + SizeOf(mhf2);
    for i := 0 to v2Count - 1 do
    begin
      Validate(SizeOf(cf2), 'Truncated V2 control');
      inFile.ReadBuffer(cf2, SizeOf(cf2));
      if (cf2.magic <> 'pfcq') or (cf2.version <> $20000) then
        raise Exception.Create('Invalid V2 control file');

      bs := IfThen(cf2.blocksize > 0, cf2.blocksize, defaultBlockSize);

      with ResultV2[i] do
      begin
        Offset := payloadOff;
        ChunkType := Type2Ext(cf2._type);
        if ChunkType = '.unk' then
          ChunkType := Format('.unk_%d', [i]);
        BlockSize := bs;
        ReadRunRecords(cf2.nrecords, bs, RR, True, BlockCount, Size);
      end;
    end;
  end;

  Result.V1 := ResultV1;
  Result.V2 := ResultV2;
end;

function AnalyzeMFCQChunks(const FileName: string): TMFCQChunkArrays;
var
  inFile: TFileStream;
begin
  if not FileExists(FileName) then
    raise Exception.CreateFmt('Input file not found: %s', [FileName]);

  inFile := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
  try
    Result := AnalyzeMFCQChunks(inFile);
  finally
    inFile.Free;
  end;
end;

procedure Chunk2Stream(inFile: TStream; const chunk: TMFCQChunk; outFile: TStream;
  cb: TProgressCallback = nil; outFileName: string = '');
var
  i, j, k: integer;
  buf, padBuf: TBytes;
  baseOffset: int64;
  targetOffset, gapSize: int64;
begin
  SetLength(buf, chunk.BlockSize);
  SetLength(padBuf, chunk.BlockSize);
  FillChar(padBuf[0], chunk.BlockSize, $FF);

  inFile.Position := chunk.Offset;
  if Assigned(cb) then
    cb(outFileName, -1, chunk.BlockCount);

  baseOffset := 0;
  if Length(chunk.RR) > 0 then
    baseOffset := chunk.RR[0].Offset;

  k := 0;
  for i := 0 to Length(chunk.RR) - 1 do
  begin
    for j := 0 to chunk.RR[i].Count - 1 do
    begin
      targetOffset := int64(chunk.BlockSize) * ((chunk.RR[i].Offset + j) - baseOffset);

      if outFile.Position < targetOffset then
      begin
        gapSize := targetOffset - outFile.Position;
        while gapSize > 0 do
        begin
          if gapSize >= chunk.BlockSize then
          begin
            outFile.WriteBuffer(padBuf[0], chunk.BlockSize);
            Dec(gapSize, chunk.BlockSize);
          end
          else
          begin
            outFile.WriteBuffer(padBuf[0], gapSize);
            gapSize := 0;
          end;
        end;
      end;

      if inFile.Position + chunk.BlockSize > inFile.Size then
        raise Exception.Create('File truncated - cannot read data block');

      Inc(k);
      if Assigned(cb) then
        cb(outFileName, k, chunk.BlockCount);

      inFile.ReadBuffer(buf[0], chunk.BlockSize);
      outFile.WriteBuffer(buf[0], chunk.BlockSize);
    end;
  end;
end;

procedure SaveMFCQChunksToFiles(const FileName: string; const Chunks: TMFCQChunkArrays;
  cb: TProgressCallback = nil; const OutDir: string = '');
var
  inFile, outFile: TFileStream;
  lstFile: TStringList;
  bc, c, i: integer;
  baseFileName, targetDir, outFileName, fullPath: string;
  v: integer = 0;
  firstRunOffset: int64;
begin
  if Length(Chunks.V1) > 0 then v := v + 1;
  if Length(Chunks.V2) > 0 then v := v + 2;
  if v = 0 then Exit;

  if OutDir <> '' then
  begin
    targetDir := IncludeTrailingPathDelimiter(OutDir);
    if not DirectoryExists(targetDir) then
      ForceDirectories(targetDir);
  end
  else
    targetDir := ExtractFilePath(FileName);

  baseFileName := ExtractFileName(FileName);

  inFile := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
  try
    lstFile := TStringList.Create;
    try
      if v > 1 then
        c := High(Chunks.V2)
      else
        c := High(Chunks.V1);

      for i := 0 to c do
      begin
        if v > 1 then
        begin
          outFileName := ChangeFileExt(baseFileName, '.' + IntToStr(i) + Chunks.V2[i].ChunkType);
          bc := Chunks.V2[i].BlockCount;
        end
        else
        begin
          outFileName := ChangeFileExt(baseFileName, '.' + IntToStr(i) + Chunks.V1[i].ChunkType);
          bc := Chunks.V1[i].BlockCount;
        end;

        fullPath := targetDir + outFileName;

        outFile := TFileStream.Create(fullPath, fmCreate);
        try
          if (v and 1) = 1 then
          begin
            Chunk2Stream(inFile, Chunks.V1[i], outFile, cb, fullPath);

            firstRunOffset := 0;
            if Length(Chunks.V1[i].RR) > 0 then
              firstRunOffset := Chunks.V1[i].RR[0].Offset;

            outFileName := outFileName + '=' + IntToStr(firstRunOffset) + ',' +
              IntToStr(Chunks.V1[i].Flags);
          end
          else
            Chunk2Stream(inFile, Chunks.V2[i], outFile, cb, fullPath);

          lstFile.Add(outFileName);
        finally
          outFile.Free;
        end;

        if Assigned(cb) then
        begin
          cb(outFileName, bc, bc);
          WriteLn;
        end;
      end;

      lstFile.SaveToFile(targetDir + ChangeFileExt(baseFileName, '.lst'));
    finally
      FreeAndNil(lstFile);
    end;
  finally
    inFile.Free;
  end;
end;

procedure unpackMFCQ(fileName: string; cb: TProgressCallback = nil; const OutDir: string = '');
var
  chunks: TMFCQChunkArrays;
begin
  chunks := AnalyzeMFCQChunks(fileName);
  SaveMFCQChunksToFiles(fileName, chunks, cb, OutDir);
end;

end.
