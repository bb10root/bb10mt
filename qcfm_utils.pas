unit qcfm_utils;

{$mode ObjFPC}{$H+}{$O+}

interface

uses
  Classes, SysUtils, FileUtil, uMisc, qcfm_types;

function Type2Ext(t: integer): string;
function Ext2Type(const t: string): integer;
function Size2Blocks(const FileName: string; bs: integer = defaultBlockSize): integer;
function AnalyzeFileBlocks(const FileName: string; BlockSize: integer = 4096): TBlockRangeArray;

implementation

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
  Result := (fs + bs - 1) div bs;
end;

function AnalyzeFileBlocks(const FileName: string; BlockSize: integer = 4096): TBlockRangeArray;
var
  F: TFileStream;
  Buf: TBytes;
  BlockIndex, RangeStart: int64;
  Count, Capacity, ResLen: integer;
  InRange, isFF: boolean;
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
        isFF := IsFullFFBlock_Branchless(Buf, BytesRead - 1);
        if not isFF then
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

        if (BytesRead < BlockSize) or isFF then
        begin
          if InRange then
          begin
            AddRange(RangeStart, Count);
            InRange := False;
          end;
        end;
      end;
      Inc(BlockIndex);
    end;

    if InRange then
      AddRange(RangeStart, Count);

    SetLength(Result, ResLen);
  finally
    F.Free;
  end;
end;

end.
