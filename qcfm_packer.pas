unit qcfm_packer;

{$mode ObjFPC}{$H+}{$O+}

interface

uses
  Classes, SysUtils, Math, uMisc, qcfm_types, qcfm_utils, qcfm_streams;

function AnalyzeMFCQChunks(inFile: TStream): TMFCQChunkArrays;
function AnalyzeMFCQChunks(const FileName: string): TMFCQChunkArrays;
procedure Chunk2Stream(inFile: TStream; const chunk: TMFCQChunk;
  outFile: TStream; cb: TProgressCallback = nil; outFileName: string = '');

procedure unpackMFCQ(fileName: string; cb: TProgressCallback = nil;
  const OutDir: string = '');
procedure packMFCQ(oFile: string; const iFiles: TStringList;
  cb: TProgressCallback = nil; ver: integer = 2; fast: boolean = False;
  sign: boolean = False);
procedure _packMFCQ(outFile: TStream; const iFiles: TStringList;
  cb: TProgressCallback = nil; ver: integer = 2; fast: boolean = False;
  sign: boolean = False);

implementation

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

type
  TRRChunkArray = array of TRRChunk;

  procedure ReadRunRecords(n: integer; bs: integer; var RR: TRRChunkArray;
    useV2: boolean; var blkCount: integer; var payloadSize: int64);
  var
    k, realCount: integer;
  begin
    payloadSize := 0;
    blkCount := 0;
    realCount := 0;
    SetLength(RR, n);

    for k := 0 to n - 1 do
    begin
      if useV2 then
      begin
        Validate(SizeOf(rr2), 'Truncated - V2 run record');
        inFile.ReadBuffer(rr2, SizeOf(rr2));
        if rr2.magic <> 'rrcq' then
          raise Exception.Create('Invalid V2 run record magic');
        RR[realCount].Count := rr2.Count;
        RR[realCount].Offset := rr2.offset;
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
        RR[realCount].Count := rr1.Count;
        RR[realCount].Offset := rr1.Offset;
        Inc(realCount);
        Inc(blkCount, rr1.Count);
        Inc(payloadSize, int64(rr1.Count) * bs);
      end;
    end;

    SetLength(RR, realCount);
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

procedure Chunk2Stream(inFile: TStream; const chunk: TMFCQChunk;
  outFile: TStream; cb: TProgressCallback = nil; outFileName: string = '');
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

procedure SaveMFCQChunksToFiles(const FileName: string;
  const Chunks: TMFCQChunkArrays; cb: TProgressCallback = nil;
  const OutDir: string = '');
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
          outFileName := ChangeFileExt(baseFileName, '.' + IntToStr(i) +
            Chunks.V2[i].ChunkType);
          bc := Chunks.V2[i].BlockCount;
        end
        else
        begin
          outFileName := ChangeFileExt(baseFileName, '.' + IntToStr(i) +
            Chunks.V1[i].ChunkType);
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

            outFileName := outFileName + '=' + IntToStr(firstRunOffset) +
              ',' + IntToStr(Chunks.V1[i].Flags);
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

procedure unpackMFCQ(fileName: string; cb: TProgressCallback = nil;
  const OutDir: string = '');
var
  chunks: TMFCQChunkArrays;
begin
  chunks := AnalyzeMFCQChunks(fileName);
  SaveMFCQChunksToFiles(fileName, chunks, cb, OutDir);
end;

procedure _packMFCQ(outFile: TStream; const iFiles: TStringList;
  cb: TProgressCallback = nil; ver: integer = 2; fast: boolean = False;
  sign: boolean = False);
var
  packStream: TMFCQPackStream;
  buffer: array[0..$FFFF] of byte;
  bytesRead, i, activeFileIdx, lastFileIdx: integer;
  curVirtPos, totalBlocks, currentBlock: int64;
  fn: string;
begin
  packStream := TMFCQPackStream.Create(iFiles, cb, ver, fast, sign);
  try
    lastFileIdx := -1;

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

        if Assigned(cb) and (Length(packStream.BlockMap) > 0) then
        begin
          activeFileIdx := -1;
          for i := High(packStream.BlockMap) downto 0 do
          begin
            if curVirtPos >= packStream.BlockMap[i].VirtualOffset then
            begin
              activeFileIdx := packStream.BlockMap[i].SourceFileIdx;
              currentBlock := (packStream.BlockMap[i].FileOffset div
                packStream.BlockSize) + 1;
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
                cb(packStream.Files[lastFileIdx],
                  Size2Blocks(packStream.Files[lastFileIdx], packStream.BlockSize),
                  Size2Blocks(packStream.Files[lastFileIdx], packStream.BlockSize));

              cb(fn, -1, totalBlocks);
              lastFileIdx := activeFileIdx;
            end;

            cb(fn, currentBlock, totalBlocks);
          end;
        end;
      end;
    until bytesRead = 0;

    if Assigned(cb) and (lastFileIdx >= 0) and
      (lastFileIdx < Length(packStream.Files)) then
    begin
      fn := packStream.Files[lastFileIdx];
      totalBlocks := Size2Blocks(fn, packStream.BlockSize);
      cb(fn, totalBlocks, totalBlocks);
    end;

  finally
    packStream.Free;
  end;
end;

procedure packMFCQ(oFile: string; const iFiles: TStringList;
  cb: TProgressCallback = nil; ver: integer = 2; fast: boolean = False;
  sign: boolean = False);
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

end.
