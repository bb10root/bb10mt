unit qcfm_streams;

{$mode ObjFPC}{$H+}{$O+}

interface

uses
  Classes, SysUtils, Math, StrUtils, Generics.Collections, crc, uMisc,
  qcfm_types, qcfm_utils;

type
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
    FLastBlockIdx: integer;
    procedure BuildBlockMap;
  public
    constructor Create(ASourceStream: TStream; const AChunk: TMFCQChunk;
      AVersion: TMFCQVersion; AOwnsSource: boolean = False);
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
    FCurrentBlockMapIdx: integer;
    procedure BuildHeadersAndMap(const iFiles: TStringList; ver: integer; fast: boolean);
    function GetSourceStream(FileIdx: integer): TFileStream;
    function FindBlockIndexAtPos(Pos: int64): integer;
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


implementation
uses qcfm_packer;

{ TMFCQPackStream }

constructor TMFCQPackStream.Create(const iFiles: TStringList;
  cb: TProgressCallback; ver: integer; fast: boolean; sign: boolean);
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
  FCurrentBlockMapIdx := 0;

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

procedure TMFCQPackStream.BuildHeadersAndMap(const iFiles: TStringList;
  ver: integer; fast: boolean);
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
        flags := IfThen((Length(fileName) > 0) and
          (fileName[Length(fileName)] = '!'), 2, 0);
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
      mhf2.headersz := SizeOf(TMultiHeaderFileV1) + mhf2.length +
        mhf2.nheaders * (SizeOf(TControlFileV2) + SizeOf(TRunRecordV2));
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

function TMFCQPackStream.FindBlockIndexAtPos(Pos: int64): integer;
var
  L, R, Mid: integer;
begin
  L := 0;
  R := High(FBlockMap);
  Result := -1;
  while L <= R do
  begin
    Mid := (L + R) div 2;
    if (Pos >= FBlockMap[Mid].VirtualOffset) and
      (Pos < FBlockMap[Mid].VirtualOffset + FBlockMap[Mid].BlockSize) then
      Exit(Mid);
    if Pos < FBlockMap[Mid].VirtualOffset then
      R := Mid - 1
    else
      L := Mid + 1;
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
  srcStream: TFileStream;
  fileSize, bytesToReadFromFile: int64;
  sigOffset: int64;
  payloadBytesRead: longint;
  idx: integer;
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

  // 2. Читання пейлоаду
  if (bytesRead < totalToRead) and (curPos >= FHeaderStream.Size) and
    (curPos < FPayloadSize) then
  begin
    idx := FCurrentBlockMapIdx;
    if (idx < 0) or (idx > High(FBlockMap)) or (curPos < FBlockMap[idx].VirtualOffset) or
      (curPos >= FBlockMap[idx].VirtualOffset + FBlockMap[idx].BlockSize) then
    begin
      idx := FindBlockIndexAtPos(curPos);
    end;

    while (idx >= 0) and (idx <= High(FBlockMap)) and (bytesRead < totalToRead) and
      (curPos < FPayloadSize) do
    begin
      FCurrentBlockMapIdx := idx;
      relOffset := curPos - FBlockMap[idx].VirtualOffset;
      chunkSize := Min(totalToRead - bytesRead, FBlockMap[idx].BlockSize - relOffset);

      FillChar(bufPtr^, chunkSize, 0);
      srcStream := GetSourceStream(FBlockMap[idx].SourceFileIdx);
      fileSize := srcStream.Size;

      if FBlockMap[idx].FileOffset + relOffset < fileSize then
      begin
        bytesToReadFromFile :=
          Min(chunkSize, fileSize - (FBlockMap[idx].FileOffset + relOffset));
        if bytesToReadFromFile > 0 then
        begin
          srcStream.Position := FBlockMap[idx].FileOffset + relOffset;
          srcStream.ReadBuffer(bufPtr^, bytesToReadFromFile);
        end;
      end;

      Inc(bytesRead, chunkSize);
      Inc(curPos, chunkSize);
      Inc(bufPtr, chunkSize);
      Inc(idx);
    end;
  end;

  // 3. CRC32 для байтів пейлоаду
  if FSign and (bytesRead > 0) and (FPosition < FPayloadSize) then
  begin
    if FPosition + bytesRead <= FPayloadSize then
      payloadBytesRead := bytesRead
    else
      payloadBytesRead := FPayloadSize - FPosition;

    if payloadBytesRead > 0 then
      FCrcVal := crc32(FCrcVal, @Buffer, payloadBytesRead);
  end;

  // 4. Читання сигнатури
  if FSign and (curPos >= FPayloadSize) and (curPos < FTotalSize) then
  begin
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

constructor TMFCQChunkStream.Create(ASourceStream: TStream;
  const AChunk: TMFCQChunk; AVersion: TMFCQVersion; AOwnsSource: boolean);
begin
  inherited Create;
  FSourceStream := ASourceStream;
  FChunk := AChunk;
  FVersion := AVersion;
  FOwnsSource := AOwnsSource;
  FPosition := 0;
  FLastBlockIdx := 0;

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
      FBlockMap[MapIdx].VirtOffset :=
        int64(FChunk.BlockSize) * ((FChunk.RR[i].Offset + j) - FBaseOffset);
      FBlockMap[MapIdx].PhysOffset := CurrPhysOffset;
      Inc(CurrPhysOffset, FChunk.BlockSize);
      Inc(MapIdx);
    end;
  end;

  LastRR := FChunk.RR[High(FChunk.RR)];
  FVirtualSize := int64(FChunk.BlockSize) * ((LastRR.Offset + LastRR.Count) -
    FBaseOffset);
end;

function TMFCQChunkStream.Read(var Buffer; Count: longint): longint;
var
  BytesToRead, BytesRead, TotalRead: longint;
  BufPtr: pbyte;
  i, StartIdx: integer;
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

  StartIdx := FLastBlockIdx;
  if (StartIdx < 0) or (StartIdx > High(FBlockMap)) or
    (FPosition < FBlockMap[StartIdx].VirtOffset) then
    StartIdx := 0;

  for i := StartIdx to High(FBlockMap) do
  begin
    VirtStart := FBlockMap[i].VirtOffset;
    VirtEnd := VirtStart + FChunk.BlockSize;

    if (FPosition < VirtEnd) and ((FPosition + BytesToRead) > VirtStart) then
    begin
      FLastBlockIdx := i;
      if (FPosition + TotalRead) < VirtStart then
      begin
        ReadChunkSize := Min(VirtStart - (FPosition + TotalRead),
          BytesToRead - TotalRead);
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

end.
