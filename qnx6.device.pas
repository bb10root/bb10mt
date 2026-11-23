unit qnx6.device;

{$mode ObjFPC}{$H+}

interface

uses
  Classes,
  SysUtils,
  {$IFDEF USEGENERICS}
  Generics.Collections,
  {$ELSE}
  lgHashMap,
  {$ENDIF}
  uMisc,
  qnx6.types;

type
  {$IFDEF USEGENERICS}
  TChangedBlocks = specialize TFastHashMap<DWord, TBytes>;
  {$ELSE}
  TChangedBlocksType = specialize TGLiteHashMapLP<DWord, TBytes, DWord>;
  TChangedBlocks = TChangedBlocksType.TMap;
  {$ENDIF}

  { TQNX6_BootBlock }

  TQNX6_BootBlock = class
  private
    fMagic: DWord;
    foff_qnx6fs: DWord;
    fsSubtype: DWord;
    fsSize: DWord;
    fStream: TStream;
    fValid: boolean;
  public
    constructor Create(Stream: TStream);
    procedure Read;
    procedure Write;

    property isValid: boolean read fValid;
    property Magic: DWord read fMagic write fMagic;
    property off_qnx6fs: DWord read foff_qnx6fs write foff_qnx6fs;
    property Subtype: DWord read fsSubtype write fsSubtype;
    property Size: DWord read fsSize write fsSize;
  end;

  { TQNX6_SuperBlock }

  TQNX6_SuperBlock = class
  private
    fStream: TStream;
    fSelfPos: int64;
    fRawData: TQNX6_SuperBlockRaw;
  public
    constructor Create(Stream: TStream);
    procedure Read;
    procedure LoadFromMemory(const Buffer);
    class function IsValidRaw(const Raw: TQNX6_SuperBlockRaw): boolean; static;
    procedure Write;
    function isValid: boolean;

    property RawData: TQNX6_SuperBlockRaw read fRawData write fRawData;
    property Magic: DWord read fRawData.Magic write fRawData.Magic;
    property CRC: DWord read fRawData.CRC write fRawData.CRC;
    property Serial: QWord read fRawData.Serial write fRawData.Serial;
    property Ctime: DWord read fRawData.ctime write fRawData.ctime;
    property Atime: DWord read fRawData.atime write fRawData.atime;
    property Flags: DWord read fRawData.flags write fRawData.flags;
    property Version: word read fRawData.version write fRawData.version;
    property Rsrvblks: word read fRawData.rsrvblks write fRawData.rsrvblks;
    property VolumeID: TGuid read fRawData.volumeid write fRawData.volumeid;

    property BlockSize: DWord read fRawData.blocksize write fRawData.blocksize;
    property NumInodes: DWord read fRawData.num_inodes write fRawData.num_inodes;
    property FreeInodes: DWord read fRawData.free_inodes write fRawData.free_inodes;
    property NumBlocks: DWord read fRawData.num_blocks write fRawData.num_blocks;
    property FreeBlocks: DWord read fRawData.free_blocks write fRawData.free_blocks;
    property AllocGroup: DWord read fRawData.allocgroup write fRawData.allocgroup;

    property MigrateBlocks: DWord read fRawData.migrate_blocks
      write fRawData.migrate_blocks;
    property ScrubBlock: DWord read fRawData.scrub_block write fRawData.scrub_block;

    property SelfPos: int64 read fSelfPos write fSelfPos;
  end;

  { TQNX6VolumeDevice }

  TQNX6VolumeDevice = class
  private
    fStream: TStream;
    fBB: TQNX6_BootBlock;
    fSB0: TQNX6_SuperBlock;
    fSB1: TQNX6_SuperBlock;
    fActiveSB: TQNX6_SuperBlock;

    fDataStart: QWord;
    fBlockSize: DWord;
    fBlockShift: integer;
    fBlockMask: QWord;
    fBlockIsPowerOf2: boolean;
    fPtrsInBlock: DWord;
    fMaxBlocks: QWord;

    fSys0AreaStart: DWord;
    fSys1AreaStart: DWord;
    fUserAreaStart: DWord;

    fDirectWrite: boolean;
    fChangedBlocks: TChangedBlocks;

    procedure InitBootAndSuperBlock;
    procedure InitBlockSizeAndConstants;
    procedure InitLayoutOffsets;
    procedure ClearStructures;
  public
    constructor Create(Stream: TStream);
    destructor Destroy; override;

    procedure Open;
    procedure Flush;

    procedure ReadBlock(idx: DWord; buff: Pointer; isize: DWord = 0);
    procedure WriteBlock(idx: DWord; buff: Pointer; osize: DWord = 0);

    property Stream: TStream read fStream write fStream;
    property BootBlock: TQNX6_BootBlock read fBB;
    property ActiveSB: TQNX6_SuperBlock read fActiveSB write fActiveSB;
    property SB0: TQNX6_SuperBlock read fSB0;
    property SB1: TQNX6_SuperBlock read fSB1;

    property DataStart: QWord read fDataStart write fDataStart;
    property BlockSize: DWord read fBlockSize write fBlockSize;
    property BlockShift: integer read fBlockShift;
    property BlockMask: QWord read fBlockMask;
    property BlockIsPowerOf2: boolean read fBlockIsPowerOf2;
    property PtrsInBlock: DWord read fPtrsInBlock write fPtrsInBlock;
    property MaxBlocks: QWord read fMaxBlocks write fMaxBlocks;

    property Sys0AreaStart: DWord read fSys0AreaStart write fSys0AreaStart;
    property Sys1AreaStart: DWord read fSys1AreaStart write fSys1AreaStart;
    property UserAreaStart: DWord read fUserAreaStart write fUserAreaStart;

    property DirectWrite: boolean read fDirectWrite write fDirectWrite;
    property ChangedBlocks: TChangedBlocks read fChangedBlocks;
  end;

implementation

{ TQNX6_BootBlock }

constructor TQNX6_BootBlock.Create(Stream: TStream);
begin
  inherited Create;
  fStream := Stream;
  fValid := False;
  Read;
end;

procedure TQNX6_BootBlock.Read;
begin
  fValid := False;
  if fStream.Size < 16 then Exit;

  fStream.Seek(0, soBeginning);
  fMagic := fStream.ReadDWord;
  if (fMagic and $FFFFFF) = (QNX_BOOT_MAGIC and $FFFFFF) then
  begin
    foff_qnx6fs := fStream.ReadDWord;
    fsSubtype := fStream.ReadDWord;
    fsSize := fStream.ReadDWord;
    fValid := True;
  end;
end;

procedure TQNX6_BootBlock.Write;
begin
  fStream.Seek(0, soBeginning);
  fStream.WriteDWord(fMagic);
  fStream.WriteDWord(foff_qnx6fs);
  fStream.WriteDWord(fsSubtype);
  fStream.WriteDWord(fsSize);
end;

{ TQNX6_SuperBlock }

constructor TQNX6_SuperBlock.Create(Stream: TStream);
begin
  inherited Create;
  fStream := Stream;
end;

class function TQNX6_SuperBlock.IsValidRaw(const Raw: TQNX6_SuperBlockRaw): boolean;
var
  chk: DWord;
begin
  chk := CRC32_QNX(@Raw.Serial, SizeOf(TQNX6_SuperBlockRaw) - 8);

  Result :=
    ((Raw.Magic = QNX6FS_SIGNATURE) or (Raw.Magic = QNX6FS_SIGNATURE2)) and
    (chk = Raw.CRC);
end;

function TQNX6_SuperBlock.isValid: boolean;
begin
  Result := IsValidRaw(fRawData);
end;

procedure TQNX6_SuperBlock.LoadFromMemory(const Buffer);
begin
  Move(Buffer, fRawData, SizeOf(fRawData));
end;

procedure TQNX6_SuperBlock.Read;
begin
  fStream.Seek(fSelfPos, soBeginning);
  fStream.ReadBuffer(fRawData, SizeOf(fRawData));
end;

procedure TQNX6_SuperBlock.Write;
begin
  fRawData.CRC := CRC32_QNX(@fRawData.Serial, SizeOf(TQNX6_SuperBlockRaw) - 8);
  fStream.Seek(fSelfPos, soBeginning);
  fStream.WriteBuffer(fRawData, SizeOf(fRawData));
end;

{ TQNX6VolumeDevice }

constructor TQNX6VolumeDevice.Create(Stream: TStream);
begin
  inherited Create;
  fStream := Stream;
  fDirectWrite := False;
  {$IFDEF USEGENERICS}
  fChangedBlocks := TChangedBlocks.Create;
  {$ELSE}
  fChangedBlocks.Clear;
  {$ENDIF}
end;

procedure TQNX6VolumeDevice.ClearStructures;
begin
  // ActiveSB may be a newly created superblock owned by the device.
  if (fActiveSB <> nil) and (fActiveSB <> fSB0) and (fActiveSB <> fSB1) then
    FreeAndNil(fActiveSB);
  fActiveSB := nil;
  FreeAndNil(fSB1);
  FreeAndNil(fSB0);
  FreeAndNil(fBB);
end;

destructor TQNX6VolumeDevice.Destroy;
begin
  ClearStructures;
  {$IFDEF USEGENERICS}
  FreeAndNil(fChangedBlocks);
  {$ELSE}
  fChangedBlocks.Clear;
  {$ENDIF}
  inherited Destroy;
end;

procedure TQNX6VolumeDevice.Open;
begin
  ClearStructures;
  InitBootAndSuperBlock;
  InitBlockSizeAndConstants;
  InitLayoutOffsets;
end;

procedure TQNX6VolumeDevice.InitBootAndSuperBlock;
const
  SEARCH_SIZE = $10000;
  STEP_SIZE = $200;
var
  Buffer: TBytes;
  SearchSize: integer;
  Offset: integer;
  Magic: DWord;
begin
  if fStream.Size < SizeOf(DWord) then
    raise Exception.Create('Stream is too short.');

  { BootBlock }

  fStream.Seek(0, soBeginning);
  Magic := fStream.ReadDWord;

  if (Magic and $FFFFFF) = (QNX_BOOT_MAGIC and $FFFFFF) then
  begin
    fBB := TQNX6_BootBlock.Create(fStream);

    if not fBB.isValid then
      FreeAndNil(fBB);
  end;

  { read first 64 KB once }

  SearchSize := SEARCH_SIZE;

  if SearchSize > fStream.Size then
    SearchSize := fStream.Size;

  SetLength(Buffer, SearchSize);

  fStream.Seek(0, soBeginning);
  fStream.ReadBuffer(Buffer[0], SearchSize);

  fSB0 := nil;

  Offset := 0;

  while Offset + SizeOf(TQNX6_SuperBlockRaw) <= SearchSize do
  begin
    if TQNX6_SuperBlock.IsValidRaw(PQNX6_SuperBlockRaw(@Buffer[Offset])^) then
    begin
      fSB0 := TQNX6_SuperBlock.Create(fStream);
      fSB0.SelfPos := Offset;
      fSB0.LoadFromMemory(Buffer[Offset]);

      fActiveSB := fSB0;
      fBlockSize := fSB0.BlockSize;
      Break;
    end;

    Inc(Offset, STEP_SIZE);
  end;

  if fSB0 = nil then
    raise Exception.Create('Can''t find superblock.');

  if Assigned(fBB) and (fBB.Subtype = 8) then
  begin
    fSB1 := TQNX6_SuperBlock.Create(fStream);

    fSB1.SelfPos := fStream.Size - fBlockSize;

    if fSB1.SelfPos >= 0 then
    begin
      fSB1.Read;

      if fSB1.isValid then
      begin
        if fSB1.Serial > fSB0.Serial then
          fActiveSB := fSB1;
      end
      else
        FreeAndNil(fSB1);
    end
    else
      FreeAndNil(fSB1);
  end;
end;

procedure TQNX6VolumeDevice.InitBlockSizeAndConstants;
begin
  fBlockSize := fActiveSB.BlockSize;
  if fBlockSize = 0 then
    raise Exception.Create('Invalid block size (0) in superblock');

  fPtrsInBlock := fBlockSize div SizeOf(DWord);
  fMaxBlocks := QWord(QNX6FS_DIRECT_BLKS) * fPtrsInBlock * fPtrsInBlock;

  fBlockIsPowerOf2 := (fBlockSize and (fBlockSize - 1)) = 0;

  if fBlockIsPowerOf2 then
  begin
    fBlockShift := BsrQWord(fBlockSize);
    fBlockMask := fBlockSize - 1;
  end
  else
  begin
    fBlockShift := -1;
    fBlockMask := 0;
  end;
end;

procedure TQNX6VolumeDevice.InitLayoutOffsets;
var
  rInodes, rBitmapBytes, rBitmapBlocks: DWord;
  sbRaw: TQNX6_SuperBlockRaw;

  function NeededExtraBlocksLocal(r2: integer): integer;
  var
    level1, level2: integer;
  begin
    if r2 <= 16 then Exit(0);
    level1 := iceil(r2, fPtrsInBlock);
    Result := level1;
    if level1 > 16 then
    begin
      level2 := iceil(level1, fPtrsInBlock);
      Result := Result + level2;
    end;
  end;

begin
  sbRaw := fActiveSB.RawData;

  rInodes := iceil(sbRaw.num_inodes * SizeOf(TQNX6_DInode), fBlockSize);
  rBitmapBytes := iceil(sbRaw.num_blocks, 8);
  rBitmapBlocks := iceil(rBitmapBytes, fBlockSize);

  fSys0AreaStart := 0;
  fSys1AreaStart := rInodes + NeededExtraBlocksLocal(rInodes) +
    rBitmapBlocks + NeededExtraBlocksLocal(rBitmapBlocks);
  fUserAreaStart := 2 * fSys1AreaStart;

  if fBlockSize <= 4096 then
    fDataStart := QNX6FS_BOOT_RSRV + QNX6FS_SBLK_RSRV
  else
    fDataStart := fBlockSize;
end;

procedure TQNX6VolumeDevice.ReadBlock(idx: DWord; buff: Pointer; isize: DWord = 0);
var
  Data: TBytes;
  blockSizeToRead: DWord;
  readCount: integer;
  copyLen: DWord;
begin
  if buff = nil then Exit;

  if isize = 0 then
    blockSizeToRead := fBlockSize
  else
    blockSizeToRead := isize;

  if Assigned(fActiveSB) and (idx >= fActiveSB.NumBlocks) then
    raise Exception.CreateFmt('Block index out of bounds: %d', [idx]);

  if fChangedBlocks.TryGetValue(idx, Data) then
  begin
    copyLen := Length(Data);
    if copyLen > blockSizeToRead then
      copyLen := blockSizeToRead;

    if copyLen > 0 then
      Move(Data[0], buff^, copyLen);

    if copyLen < blockSizeToRead then
      FillChar(pbyte(buff)[copyLen], blockSizeToRead - copyLen, 0);
  end
  else
  begin
    fStream.Seek(fDataStart + int64(idx) * fBlockSize, soBeginning);

    readCount := fStream.Read(buff^, blockSizeToRead);
    if readCount < 0 then readCount := 0;

    if DWord(readCount) < blockSizeToRead then
      FillChar(pbyte(buff)[readCount], blockSizeToRead - DWord(readCount), 0);
  end;
end;

procedure TQNX6VolumeDevice.WriteBlock(idx: DWord; buff: Pointer; osize: DWord = 0);
var
  Data: TBytes;
  sizeToWrite: DWord;
begin
  if buff = nil then Exit;

  if osize = 0 then
    sizeToWrite := fBlockSize
  else
    sizeToWrite := osize;

  if fDirectWrite then
  begin
    fStream.Seek(fDataStart + int64(idx) * fBlockSize, soBeginning);
    fStream.WriteBuffer(buff^, sizeToWrite);
  end
  else
  begin
    SetLength(Data, sizeToWrite);
    if sizeToWrite > 0 then
      Move(buff^, Data[0], sizeToWrite);

    fChangedBlocks.AddOrSetValue(idx, Data);
  end;
end;

procedure TQNX6VolumeDevice.Flush;
var
  blkData: TBytes;
  blk: DWord;
  {$IFDEF USEGENERICS}
  Pair: TChangedBlocks.TDictionaryPair;
  {$ELSE}
  Pair: TChangedBlocksType.TEntry;
  {$ENDIF}
begin
  fDirectWrite := True;
  try
    for Pair in fChangedBlocks do
    begin
      blk := Pair.Key;
      blkData := Pair.Value;
      if Length(blkData) > 0 then
        WriteBlock(blk, @blkData[0], Length(blkData));
    end;
  finally
    fChangedBlocks.Clear;
    fDirectWrite := False;
  end;

  if Assigned(fActiveSB) then
    fActiveSB.Write;
end;

end.
