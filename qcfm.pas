unit qcfm;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, uMisc;

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

function AnalyzeMFCQChunks(inFile: TStream): TMFCQChunkArrays;
function AnalyzeMFCQChunks(const FileName: string): TMFCQChunkArrays;
procedure Chunk2Stream(inFile: TStream; const chunk: TMFCQChunk; outFile: TStream;
  cb: TProgressCallback = nil; outFileName: string = '');

procedure unpackMFCQ(fileName: string; cb: TProgressCallback = nil; const OutDir: string = '');
procedure packMFCQ(oFile: string; const iFiles: TStringList; cb: TProgressCallback = nil;
  ver: integer = 2; fast: boolean = False);
procedure _packMFCQ(outFile: TStream; const iFiles: TStringList; cb: TProgressCallback = nil;
  ver: integer = 2; fast: boolean = False);


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

uses Math, crc, StrUtils, FileUtil;

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

function AnalyzeFileBlocks(const FileName: string; BlockSize: integer = 4096): TBlockRangeArray;
var
  F: TFileStream;
  Buf: TBytes;
  BlockIndex: int64;
  RangeStart: int64;
  Count: integer;
  InRange: boolean;
  BytesRead: integer;
begin
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
        end
        else
        begin
          if InRange then
          begin
            SetLength(Result, Length(Result) + 1);
            Result[High(Result)].BlockIndex := RangeStart;
            Result[High(Result)].Count := Count;
            InRange := False;
          end;
        end;

        if Length(Buf) <> BlockSize then
          SetLength(Buf, BlockSize);
      end;

      Inc(BlockIndex);
    end;

    if InRange then
    begin
      SetLength(Result, Length(Result) + 1);
      Result[High(Result)].BlockIndex := RangeStart;
      Result[High(Result)].Count := Count;
    end;
  finally
    F.Free;
  end;
end;

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

procedure _packMFCQ(outFile: TStream; const iFiles: TStringList; cb: TProgressCallback = nil;
  ver: integer = 2; fast: boolean = False);
type
  TXRec = record
    cf1: TControlFileV1;
    cf2: TControlFileV2;
    arr1: array of TRunRecordV1;
    arr2: array of TRunRecordV2;
  end;
var
  inFile: TFileStream;
  mhf1: TMultiHeaderFileV1;
  mhf2: TMultiHeaderFileV2;
  XRec: array of TXRec;
  flags, i, j, k, s, bs, c: integer;
  buf: TBytes;
  tmps, params: TStringArray;
  fileName: string;
  blockIdx, blockOffset: int64;
  totalFiles: integer;
  range: TBlockRange;
  XBRA: array of TBlockRangeArray;
  xPos, Delta: int64;
  dataSize, totalSize: int64;

  function GetValue(n: integer): cardinal;
  begin
    if n <= 3 then
      Result := 3
    else
      Result := 7 + ((n - 4) div 4) * 4;
  end;

begin
  if not Assigned(iFiles) or (iFiles.Count = 0) then
    raise Exception.Create('No input files specified');

  bs := defaultBlockSize;
  totalFiles := iFiles.Count;
  fast := (ver = 2);
  SetLength(XRec, totalFiles);
  SetLength(XBRA, totalFiles);

  FillChar(mhf1, SizeOf(mhf1), 0);
  mhf1.magic := 'mfcq';
  mhf1.version := 1;
  mhf1.nheaders := totalFiles;
  mhf1.flags := IfThen(ver > 1, SizeOf(TMultiHeaderFileV1), 0);

  for i := 0 to totalFiles - 1 do
  begin
    // Виправлений парсинг "filename=delta,flags"
    tmps := SplitString(iFiles[i], '=');
    fileName := ExpandFileName(tmps[0]);

    Delta := 0;
    Flags := 0;

    if Length(tmps) > 1 then
    begin
      params := SplitString(tmps[1], ',');
      if Length(params) > 0 then
        Delta := StrToIntDef(params[0], 0);
      if Length(params) > 1 then
        Flags := StrToIntDef(params[1], 0)
      else
        Flags := IfThen((Length(fileName) > 0) and (fileName[Length(fileName)] = '!'), 2, 0);
    end;

    if not FileExists(fileName) then
      raise Exception.CreateFmt('Input file not found: %s', [fileName]);

    if fast then
    begin
      SetLength(XBRA[i], 1);
      XBRA[i][0].BlockIndex := 0;
      XBRA[i][0].Count := Size2Blocks(fileName, bs);
    end
    else
      XBRA[i] := AnalyzeFileBlocks(fileName, bs);

    c := Length(XBRA[i]);
    with XRec[i] do
    begin
      if (ver and 1) = 1 then
      begin
        FillChar(cf1, SizeOf(cf1), 0);
        cf1.magic := 'qcfp';
        cf1.version := 1;
        cf1.blocksize := bs;
        cf1.device := 0;
        cf1.flags := Flags;
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
        cf2.blocksize := bs;
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

  // V2 Multiheader
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

  // === Write V1 headers ===
  outFile.Position := SizeOf(mhf1);
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
        SetLength(buf, totalSize);
        Move(cf1, buf[0], SizeOf(TControlFileV1));
        if dataSize > 0 then
          Move(arr1[0], buf[SizeOf(TControlFileV1)], dataSize);

        cf1.checksum := crc32(0, @buf[8], totalSize - 8);
        Move(cf1, buf[0], SizeOf(TControlFileV1));
        outFile.WriteBuffer(buf[0], totalSize);
      end;
    end;
  end;

  xPos := outFile.Position;
  mhf1.flags := xPos;

  outFile.Position := 0;
  outFile.WriteBuffer(mhf1, SizeOf(mhf1));
  outFile.Position := xPos;

  // === Write V2 headers ===
  if (ver and 2) = 2 then
  begin
    outFile.WriteBuffer(mhf2, SizeOf(mhf2));
    for i := 0 to totalFiles - 1 do
    begin
      with XRec[i] do
      begin
        outFile.WriteBuffer(cf2, SizeOf(TControlFileV2));
        if cf2.nrecords > 0 then
          outFile.WriteBuffer(arr2[0], cf2.nrecords * SizeOf(TRunRecordV2));
      end;
    end;
  end;

  // === Write data blocks ===
  outFile.Position := mhf1.headersz;
  SetLength(buf, bs);
  for i := 0 to totalFiles - 1 do
  begin
    tmps := SplitString(iFiles[i], '=');
    fileName := ExpandFileName(tmps[0]);
    inFile := TFileStream.Create(fileName, fmOpenRead or fmShareDenyNone);
    try
      if Assigned(cb) then
        cb(fileName, -1, inFile.Size div bs);
      for j := 0 to High(XBRA[i]) do
      begin
        range := XBRA[i][j];
        for k := 0 to range.Count - 1 do
        begin
          blockIdx := range.BlockIndex + k;
          blockOffset := blockIdx * bs;
          if blockOffset >= inFile.Size then Continue;

          s := bs;
          if blockOffset + bs > inFile.Size then
            s := inFile.Size - blockOffset;

          if s <= 0 then Continue;

          if Assigned(cb) then
            cb(fileName, blockOffset div bs, inFile.Size div bs);

          inFile.Position := blockOffset;
          FillChar(buf[0], bs, 0);
          inFile.ReadBuffer(buf[0], s);
          outFile.WriteBuffer(buf[0], bs);
        end;
      end;

      if Assigned(cb) then
        cb(fileName, inFile.Size div bs, inFile.Size div bs);
    finally
      inFile.Free;
    end;
  end;
end;

procedure packMFCQ(oFile: string; const iFiles: TStringList; cb: TProgressCallback = nil;
  ver: integer = 2; fast: boolean = False);
var
  outFile: TFileStream;
begin
  if oFile = '' then
    raise Exception.Create('Output file name cannot be empty');

  outFile := TFileStream.Create(ExpandFileName(oFile), fmCreate);
  try
    _packMFCQ(outFile, iFiles, cb, ver, fast);
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

      // Якщо є розрив в адресації блоків, заповнюємо $FF
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

  // Визначаємо цільову директорію для збереження
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

        // Повний шлях для створення вихідного файлу
        fullPath := targetDir + outFileName;

        outFile := TFileStream.Create(fullPath, fmCreate);
        try
          if (v and 1) = 1 then
          begin
            Chunk2Stream(inFile, Chunks.V1[i], outFile, cb, fullPath);

            // Безпечна перевірка наявності елемента у масиві RR
            firstRunOffset := 0;
            if Length(Chunks.V1[i].RR) > 0 then
              firstRunOffset := Chunks.V1[i].RR[0].Offset;

            // Формуємо відносне ім'я для списку lst з метаданими
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

      // Зберігаємо .lst у цільову директорію
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
