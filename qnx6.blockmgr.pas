unit qnx6.blockmgr;

{$mode ObjFPC}{$H+}
{$O+}

interface

uses
  Classes,
  SysUtils,
  Math,
  bits,
  uMisc,
  qnx6.device,
  qnx6.types;

type
  { TQNX6BlockManager }

  TQNX6BlockManager = class
  private
    fDevice: TQNX6VolumeDevice;
    fBitmapBlocks: TBlocksList;
    fBitmap: XBits;
    fFreeBlocks: TFreeBlocks;
    fIsChanged: boolean;
    fLastSearchIdx: DWord;

    function IsValidBlock(BlockNo: DWord): boolean; inline;
    function IsAllocatableBlock(BlockNo: DWord; SystemBlock: boolean): boolean; inline;

    function RequiredLevel1(DataCount: integer): integer; inline;
    function RequiredLevel2(Level1Count: integer): integer; inline;
    function RequiredTop(DataCount: integer): integer; inline;

    function AllocateOneBlock(SystemBlock: boolean): DWord;
    procedure RollbackBlocks(const Blocks: TDwordArray);

    procedure ClearLevel(var Level: TLevelData);
    procedure AddBlockToLevel(var Level: TLevelData; BlockNo: DWord);
  public
    constructor Create(ADevice: TQNX6VolumeDevice);
    destructor Destroy; override;

    procedure LoadBitmap;

    function AllocateBlocks(Count: integer; SystemBlock: boolean = False): TDwordArray;

    procedure FreeBlocks(const Blocks: TDwordArray);

    procedure LoadBlocks(var xBlocks: TQNX6_DB; level: DWord;
      size: QWord; var Blocks: TBlocksList);

    procedure SaveBlocks(var xBlocks: TQNX6_DB; var Blocks: TBlocksList);

    procedure LoadBlockData(var Blocks: TBlocksList; Data: Pointer; size: QWord);

    procedure SaveBlockData(var Blocks: TBlocksList; Data: Pointer; size: QWord);

    function AddBlockToChain(var Blocks: TBlocksList;
      systemBlock: boolean = False): DWord;

    function RemoveBlockFromChain(var Blocks: TBlocksList; id: DWord;
      idx: integer = -1): TDwordArray;

    procedure Flush;

    property Device: TQNX6VolumeDevice read fDevice;
    property Bitmap: XBits read fBitmap;
    property BitmapBlocks: TBlocksList read fBitmapBlocks write fBitmapBlocks;
    property IsChanged: boolean read fIsChanged write fIsChanged;
  end;

implementation

{ TQNX6BlockManager }

constructor TQNX6BlockManager.Create(ADevice: TQNX6VolumeDevice);
begin
  inherited Create;

  fDevice := ADevice;

  fFreeBlocks := TFreeBlocks.Create;
  fBitmap := XBits.Create;

  fIsChanged := False;
  fLastSearchIdx := 0;

  fBitmapBlocks := Default(TBlocksList);
end;

destructor TQNX6BlockManager.Destroy;
begin
  FreeAndNil(fFreeBlocks);
  FreeAndNil(fBitmap);

  inherited Destroy;
end;

function TQNX6BlockManager.IsValidBlock(BlockNo: DWord): boolean;
begin
  Result :=
    (fDevice <> nil) and (fDevice.ActiveSB <> nil) and
    (BlockNo < fDevice.ActiveSB.NumBlocks);
end;

function TQNX6BlockManager.IsAllocatableBlock(BlockNo: DWord;
  SystemBlock: boolean): boolean;
begin
  Result := IsValidBlock(BlockNo);

  if not Result then
    Exit;

  if SystemBlock then
    Exit(True);

  Result := BlockNo >= fDevice.UserAreaStart;
end;

function TQNX6BlockManager.RequiredLevel1(DataCount: integer): integer;
begin
  if DataCount <= QNX6FS_DIRECT_BLKS then
    Exit(0);

  Result := iceil(DataCount, fDevice.PtrsInBlock);
end;

function TQNX6BlockManager.RequiredLevel2(Level1Count: integer): integer;
begin
  if Level1Count <= 0 then
    Exit(0);

  Result := iceil(Level1Count, fDevice.PtrsInBlock);
end;

function TQNX6BlockManager.RequiredTop(DataCount: integer): integer;
var
  P: QWord;
  MaxLevel1: QWord;
  MaxLevel2: QWord;
begin
  Result := -1;

  if DataCount <= 0 then
    Exit;

  P := fDevice.PtrsInBlock;

  if P = 0 then
    Exit;

  { top = 0: 16 root entries -> 16 DATA }
  if QWord(DataCount) <= QNX6FS_DIRECT_BLKS then
  begin
    Result := 0;
    Exit;
  end;

  { top = 1: 16 root entries -> L1; each L1 -> P DATA }
  MaxLevel1 := QWord(QNX6FS_DIRECT_BLKS) * P;

  if QWord(DataCount) <= MaxLevel1 then
  begin
    Result := 1;
    Exit;
  end;

  { top = 2: 16 root entries -> L2; each L2 -> P L1; each L1 -> P DATA }
  MaxLevel2 := QWord(QNX6FS_DIRECT_BLKS) * P * P;

  if QWord(DataCount) <= MaxLevel2 then
  begin
    Result := 2;
    Exit;
  end;
end;

procedure TQNX6BlockManager.ClearLevel(var Level: TLevelData);
begin
  Level.Count := 0;
  SetLength(Level.Data, 0);
end;

procedure TQNX6BlockManager.AddBlockToLevel(var Level: TLevelData; BlockNo: DWord);
begin
  if Level.Count >= Length(Level.Data) then
    SetLength(
      Level.Data,
      Max(16, integer(Level.Count) + 16)
      );

  Level.Data[Level.Count] := BlockNo;
  Inc(Level.Count);
end;

procedure TQNX6BlockManager.LoadBitmap;
var
  bitmapSize: QWord;
begin
  if (fDevice = nil) or (fDevice.ActiveSB = nil) then Exit;

  with fDevice.ActiveSB.RawData do
  begin
    fBitmap.Size := num_blocks;
    bitmapSize := iceil(num_blocks, 8);
    // Точний розмір бітмапа у байтах

    LoadBlocks(bitmap.blocks, bitmap.indirect, bitmapSize, fBitmapBlocks);
    LoadBlockData(fBitmapBlocks, fBitmap.BitsPtr, bitmapSize);
  end;
  fLastSearchIdx := 0;
end;


function TQNX6BlockManager.AllocateOneBlock(SystemBlock: boolean): DWord;
var
  TotalBlocks: QWord;
  StartBlock: QWord;
  WordsCount: QWord;
  P: PDWord;

  function ScanRange(AStart, AEnd: QWord): DWord;
  var
    I: QWord;
    WordIdx: QWord;
    BitIdx: QWord;
    BlockNo: DWord;
  begin
    Result := $FFFFFFFF;
    I := AStart;

    while I < AEnd do
    begin
      if IsAllocatableBlock(DWord(I), SystemBlock) then
      begin
        WordIdx := I div 32;
        BitIdx := I mod 32;

        if (BitIdx = 0) and (WordIdx < WordsCount) and (P[WordIdx] = $FFFFFFFF) then
        begin
          Inc(I, 32);
          Continue;
        end;

        if not fBitmap.Get(I) then
        begin
          BlockNo := DWord(I);
          fBitmap.SetOn(BlockNo);
          Inc(BlockNo);

          if SystemBlock then
            fLastSearchIdx := BlockNo
          else
            fLastSearchIdx := Max(DWord(fDevice.UserAreaStart), BlockNo);

          Exit(I);
        end;
      end;
      Inc(I);
    end;
  end;

begin
  Result := $FFFFFFFF;

  if (fDevice = nil) or (fDevice.ActiveSB = nil) then
    Exit;

  TotalBlocks := fBitmap.Size;
  if TotalBlocks = 0 then
    Exit;

  StartBlock := fLastSearchIdx;

  if SystemBlock then
  begin
    if StartBlock >= TotalBlocks then
      StartBlock := 0;
  end
  else
  begin
    if StartBlock < fDevice.UserAreaStart then
      StartBlock := fDevice.UserAreaStart;

    if StartBlock >= TotalBlocks then
      StartBlock := fDevice.UserAreaStart;

    if StartBlock >= TotalBlocks then
      Exit;
  end;

  WordsCount := iceil(TotalBlocks, 32);
  P := PDWord(fBitmap.BitsPtr);

  { First pass }
  Result := ScanRange(StartBlock, TotalBlocks);
  if Result <> $FFFFFFFF then
    Exit;

  { Cyclic second pass }
  if SystemBlock then
    Result := ScanRange(0, StartBlock)
  else if StartBlock > fDevice.UserAreaStart then
    Result := ScanRange(fDevice.UserAreaStart, StartBlock);
end;

procedure TQNX6BlockManager.RollbackBlocks(const Blocks: TDwordArray);
var
  I: integer;
  BlockNo: DWord;
begin
  for I := 0 to High(Blocks) do
  begin
    BlockNo := Blocks[I];

    if not IsValidBlock(BlockNo) then
      Continue;

    if fBitmap.Get(BlockNo) then
    begin
      fBitmap.Clear(BlockNo);
      fFreeBlocks.Enqueue(BlockNo);
    end;
  end;
end;

function TQNX6BlockManager.AllocateBlocks(Count: integer;
  SystemBlock: boolean): TDwordArray;
var
  BlockNo: DWord;
  Found: integer;
  Deferred: TDwordArray;
  DeferredCount: integer;
begin
  SetLength(Result, 0);

  if Count <= 0 then
    Exit;

  if (fDevice = nil) or (fDevice.ActiveSB = nil) then
    Exit;

  if fBitmap.Size = 0 then
    Exit;

  if QWord(Count) > QWord(fDevice.ActiveSB.FreeBlocks) then
    Exit;

  SetLength(Result, Count);

  Found := 0;
  DeferredCount := 0;
  SetLength(Deferred, fFreeBlocks.Count);

  { Reuse blocks from the free queue }
  while (Found < Count) and (fFreeBlocks.Count > 0) do
  begin
    BlockNo := $FFFFFFFF;

    {$IFDEF USEGENERICS}
    BlockNo := fFreeBlocks.Dequeue;
    {$ELSE}
    if not fFreeBlocks.TryDequeue(BlockNo) then
      Break;
    {$ENDIF}

    if not IsValidBlock(BlockNo) then
      Continue;

    if not IsAllocatableBlock(BlockNo, SystemBlock) then
    begin
      Deferred[DeferredCount] := BlockNo;
      Inc(DeferredCount);
      Continue;
    end;

    if fBitmap.Get(BlockNo) then
      Continue;

    fBitmap.SetOn(BlockNo);

    Result[Found] := BlockNo;
    Inc(Found);
  end;

  SetLength(Deferred, DeferredCount);

  { Return deferred blocks to queue }
  while DeferredCount > 0 do
  begin
    Dec(DeferredCount);
    fFreeBlocks.Enqueue(Deferred[DeferredCount]);
  end;

  { Bitmap search }
  while Found < Count do
  begin
    BlockNo := AllocateOneBlock(SystemBlock);

    if BlockNo = $FFFFFFFF then
      Break;

    Result[Found] := BlockNo;
    Inc(Found);
  end;

  { Atomic allocation }
  if Found <> Count then
  begin
    SetLength(Result, Found);
    RollbackBlocks(Result);
    SetLength(Result, 0);
    Exit;
  end;

  if Found > 0 then
  begin
    fDevice.ActiveSB.FreeBlocks :=
      fDevice.ActiveSB.FreeBlocks - DWord(Found);

    fIsChanged := True;
  end;
end;

procedure TQNX6BlockManager.FreeBlocks(const Blocks: TDwordArray);
var
  BlockNo: DWord;
  TotalBlocks: DWord;
  FreedCount: DWord;
begin
  if (Length(Blocks) = 0) or (fDevice = nil) or (fDevice.ActiveSB = nil) then
    Exit;

  TotalBlocks := fDevice.ActiveSB.NumBlocks;
  FreedCount := 0;

  for BlockNo in Blocks do
  begin
    if (BlockNo = $FFFFFFFF) or (BlockNo >= TotalBlocks) then
      Continue;

    if fBitmap.Get(BlockNo) then
    begin
      fBitmap.Clear(BlockNo);
      fFreeBlocks.Enqueue(BlockNo);
      fDevice.ChangedBlocks.Remove(BlockNo);
      Inc(FreedCount);
    end;
  end;

  if FreedCount > 0 then
  begin
    fDevice.ActiveSB.FreeBlocks :=
      fDevice.ActiveSB.FreeBlocks + FreedCount;

    fIsChanged := True;
  end;
end;

procedure TQNX6BlockManager.LoadBlocks(var xBlocks: TQNX6_DB; level: DWord;
  size: QWord; var Blocks: TBlocksList);
var
  TotalDataBlocks: QWord;
  PointersPerBlock: integer;

  procedure AddDataBlock(BlockNo: DWord);
  begin
    if QWord(Blocks.level[0].Count) >= TotalDataBlocks then
      Exit;

    if not IsValidBlock(BlockNo) then
      Exit;

    AddBlockToLevel(Blocks.level[0], BlockNo);
  end;

  procedure GetIBlock(BlockNo: DWord; CurrentLevel: DWord);
  var
    Buff: TDwordArray;
    I: integer;
    Ptr: DWord;
  begin
    if QWord(Blocks.level[0].Count) >= TotalDataBlocks then
      Exit;

    if CurrentLevel = 0 then
    begin
      AddDataBlock(BlockNo);
      Exit;
    end;

    if CurrentLevel > 2 then
      Exit;

    if not IsValidBlock(BlockNo) then
      Exit;

    AddBlockToLevel(Blocks.level[CurrentLevel], BlockNo);

    SetLength(Buff, PointersPerBlock);
    if Length(Buff) = 0 then
      Exit;

    fDevice.ReadBlock(BlockNo, @Buff[0]);

    for I := 0 to High(Buff) do
    begin
      if QWord(Blocks.level[0].Count) >= TotalDataBlocks then
        Break;

      Ptr := Buff[I];

      if Ptr = $FFFFFFFF then
        Break;

      if not IsValidBlock(Ptr) then
        Break;

      if CurrentLevel > 1 then
        GetIBlock(Ptr, CurrentLevel - 1)
      else
        AddDataBlock(Ptr);
    end;
  end;

var
  I: integer;
begin
  for I := 0 to 2 do
    ClearLevel(Blocks.level[I]);

  Blocks.top := 0;

  if (fDevice = nil) or (fDevice.ActiveSB = nil) then
    Exit;

  if fDevice.BlockSize = 0 then
    Exit;

  if fDevice.PtrsInBlock <= 0 then
    Exit;

  if level > 2 then
    Exit;

  PointersPerBlock := fDevice.PtrsInBlock;
  TotalDataBlocks := iceil(size, fDevice.BlockSize);

  if TotalDataBlocks = 0 then
    Exit;

  Blocks.top := level;

  { Direct DATA blocks }
  if level = 0 then
  begin
    for I := 0 to High(xBlocks) do
    begin
      if QWord(Blocks.level[0].Count) >= TotalDataBlocks then
        Break;

      if xBlocks[I] = $FFFFFFFF then
        Break;

      AddDataBlock(xBlocks[I]);
    end;
    Exit;
  end;

  { Root contains indirect blocks }
  for I := 0 to High(xBlocks) do
  begin
    if QWord(Blocks.level[0].Count) >= TotalDataBlocks then
      Break;

    if xBlocks[I] = $FFFFFFFF then
      Break;

    GetIBlock(xBlocks[I], level);
  end;

  { Fit level structures to exact loaded counts }
  for I := 0 to 2 do
    SetLength(Blocks.level[I].Data, Blocks.level[I].Count);
end;


procedure TQNX6BlockManager.SaveBlocks(var xBlocks: TQNX6_DB; var Blocks: TBlocksList);
var
  Buff: TBytes;
  RootCount: integer;
  DataPos: integer;
  L1Pos: integer;
  L2Pos: integer;
  ToCopy: integer;
  SrcData: Pointer;
  BlockNo: DWord;
  I: integer;
begin
  FillByte(xBlocks[0], SizeOf(TQNX6_DB), $FF);

  if (fDevice = nil) or (fDevice.ActiveSB = nil) then
    Exit;

  if (fDevice.BlockSize = 0) or (fDevice.PtrsInBlock <= 0) then
    Exit;

  Buff := nil;

  case Blocks.top of

    { top = 0: root[16] -> DATA }
    0:
    begin
      RootCount := Min(Blocks.level[0].Count, QNX6FS_DIRECT_BLKS);

      if RootCount > 0 then
      begin
        Move(
          Blocks.level[0].Data[0],
          xBlocks[0],
          RootCount * SizeOf(DWord)
          );
      end;
    end;

    { top = 1: root[16] -> L1[P] -> DATA }
    1:
    begin
      RootCount := Min(Blocks.level[1].Count, QNX6FS_DIRECT_BLKS);

      SetLength(Buff, fDevice.BlockSize);
      DataPos := 0;

      for I := 0 to RootCount - 1 do
      begin
        BlockNo := Blocks.level[1].Data[I];

        FillByte(Buff[0], fDevice.BlockSize, $FF);

        ToCopy := Min(fDevice.PtrsInBlock, Blocks.level[0].Count - DataPos);

        if (ToCopy > 0) and (DataPos < Length(Blocks.level[0].Data)) then
        begin
          SrcData := @Blocks.level[0].Data[DataPos];

          Move(
            SrcData^,
            Buff[0],
            ToCopy * SizeOf(DWord)
            );

          Inc(DataPos, ToCopy);
        end;

        fDevice.WriteBlock(BlockNo, @Buff[0]);
        xBlocks[I] := BlockNo;

        if DataPos >= Blocks.level[0].Count then
          Break;
      end;
    end;

    { top = 2: root[16] -> L2[P] -> L1[P] -> DATA }
    2:
    begin
      RootCount := Min(Blocks.level[2].Count, QNX6FS_DIRECT_BLKS);

      SetLength(Buff, fDevice.BlockSize);

      { First create L1 blocks containing DATA pointers }
      DataPos := 0;

      for L1Pos := 0 to Blocks.level[1].Count - 1 do
      begin
        BlockNo := Blocks.level[1].Data[L1Pos];

        FillByte(Buff[0], fDevice.BlockSize, $FF);

        ToCopy := Min(fDevice.PtrsInBlock, Blocks.level[0].Count - DataPos);

        if (ToCopy > 0) and (DataPos < Length(Blocks.level[0].Data)) then
        begin
          SrcData := @Blocks.level[0].Data[DataPos];

          Move(
            SrcData^,
            Buff[0],
            ToCopy * SizeOf(DWord)
            );

          Inc(DataPos, ToCopy);
        end;

        fDevice.WriteBlock(BlockNo, @Buff[0]);

        if DataPos >= Blocks.level[0].Count then
          Break;
      end;

      { Next create L2 blocks containing L1 pointers }
      L1Pos := 0;

      for L2Pos := 0 to RootCount - 1 do
      begin
        BlockNo := Blocks.level[2].Data[L2Pos];

        FillByte(Buff[0], fDevice.BlockSize, $FF);

        ToCopy := Min(fDevice.PtrsInBlock, Blocks.level[1].Count - L1Pos);

        if (ToCopy > 0) and (L1Pos < Length(Blocks.level[1].Data)) then
        begin
          SrcData := @Blocks.level[1].Data[L1Pos];

          Move(
            SrcData^,
            Buff[0],
            ToCopy * SizeOf(DWord)
            );

          Inc(L1Pos, ToCopy);
        end;

        fDevice.WriteBlock(BlockNo, @Buff[0]);

        xBlocks[L2Pos] := BlockNo;

        if L1Pos >= Blocks.level[1].Count then
          Break;
      end;
    end;
  end;
end;

procedure TQNX6BlockManager.LoadBlockData(var Blocks: TBlocksList;
  Data: Pointer; size: QWord);
var
  I: integer;
  BlockNo: DWord;
  Position: QWord;
  TransferSize: QWord;
begin
  if (Data = nil) or (size = 0) then
    Exit;

  if (fDevice = nil) or (fDevice.BlockSize = 0) then
    Exit;

  if Blocks.level[0].Count = 0 then
    Exit;

  Position := 0;

  for I := 0 to Blocks.level[0].Count - 1 do
  begin
    if Position >= size then
      Break;

    BlockNo := Blocks.level[0].Data[I];

    if not IsValidBlock(BlockNo) then
      Break;

    TransferSize := Min(QWord(fDevice.BlockSize), size - Position);

    fDevice.ReadBlock(
      BlockNo,
      pbyte(Data) + Position,
      TransferSize
      );

    Inc(Position, TransferSize);
  end;
end;

procedure TQNX6BlockManager.SaveBlockData(var Blocks: TBlocksList;
  Data: Pointer; size: QWord);
var
  I: integer;
  BlockNo: DWord;
  Position: QWord;
  TransferSize: QWord;
  Source: pbyte;
begin
  if (Data = nil) or (size = 0) then
    Exit;

  if (fDevice = nil) or (fDevice.BlockSize = 0) then
    Exit;

  if Blocks.level[0].Count = 0 then
    Exit;

  Position := 0;
  Source := pbyte(Data);

  for I := 0 to Blocks.level[0].Count - 1 do
  begin
    if Position >= size then
      Break;

    BlockNo := Blocks.level[0].Data[I];

    if not IsValidBlock(BlockNo) then
      Break;

    TransferSize := Min(QWord(fDevice.BlockSize), size - Position);

    fDevice.WriteBlock(
      BlockNo,
      Source + Position,
      TransferSize
      );

    Inc(Position, TransferSize);
  end;
end;

function TQNX6BlockManager.AddBlockToChain(var Blocks: TBlocksList;
  systemBlock: boolean): DWord;
var
  OldDataCount, NewDataCount: integer;
  NewTop, OldL1Count, OldL2Count: integer;
  NewL1Count, NewL2Count: integer;
  NeedData, NeedL1, NeedL2, TotalNewBlocks: integer;
  NewBlocks: TDwordArray;
  DataBlock: DWord;
  I: integer;
  EmptyBuff: TBytes;
begin
  Result := $FFFFFFFF;

  if (fDevice = nil) or (fDevice.ActiveSB = nil) or (fDevice.PtrsInBlock <= 0) then
    Exit;

  OldDataCount := Blocks.level[0].Count;

  if OldDataCount >= fDevice.MaxBlocks then
    Exit;

  NewDataCount := OldDataCount + 1;
  NewTop := RequiredTop(NewDataCount);

  if NewTop < 0 then
    Exit;

  OldL1Count := Blocks.level[1].Count;
  OldL2Count := Blocks.level[2].Count;

  if NewTop >= 1 then
    NewL1Count := RequiredLevel1(NewDataCount)
  else
    NewL1Count := 0;

  if NewTop >= 2 then
    NewL2Count := RequiredLevel2(NewL1Count)
  else
    NewL2Count := 0;

  NeedData := 1;
  NeedL1 := Max(0, NewL1Count - OldL1Count);
  NeedL2 := Max(0, NewL2Count - OldL2Count);

  TotalNewBlocks := NeedData + NeedL1 + NeedL2;

  NewBlocks := AllocateBlocks(TotalNewBlocks, systemBlock);
  if Length(NewBlocks) <> TotalNewBlocks then
    Exit;

  DataBlock := NewBlocks[0];
  I := 1;

  { Initialize new index blocks on disk with $FF ($FFFFFFFF) }
  if (NeedL1 + NeedL2) > 0 then
  begin
    SetLength(EmptyBuff, fDevice.BlockSize);
    FillByte(EmptyBuff[0], fDevice.BlockSize, $FF);
    try
      while I < TotalNewBlocks do
      begin
        fDevice.WriteBlock(NewBlocks[I], @EmptyBuff[0]);
        Inc(I);
      end;
    except
      RollbackBlocks(NewBlocks);
      Exit;
    end;
  end;

  { Add newly allocated L1 blocks }
  I := 1;
  while Blocks.level[1].Count < NewL1Count do
  begin
    AddBlockToLevel(Blocks.level[1], NewBlocks[I]);
    Inc(I);
  end;

  { Add newly allocated L2 blocks }
  while Blocks.level[2].Count < NewL2Count do
  begin
    AddBlockToLevel(Blocks.level[2], NewBlocks[I]);
    Inc(I);
  end;

  { Add DATA block }
  AddBlockToLevel(Blocks.level[0], DataBlock);

  Blocks.top := NewTop;
  Result := DataBlock;
end;

function TQNX6BlockManager.RemoveBlockFromChain(var Blocks: TBlocksList;
  id: DWord; idx: integer): TDwordArray;
var
  DataCount, I: integer;
  RemovedBlock: DWord;
  NewTop, NewL1Count, NewL2Count: integer;
begin
  SetLength(Result, 0);

  DataCount := Blocks.level[0].Count;
  if DataCount <= 0 then
    Exit;

  { Locate block index if not supplied }
  if idx < 0 then
  begin
    for I := 0 to DataCount - 1 do
    begin
      if Blocks.level[0].Data[I] = id then
      begin
        idx := I;
        Break;
      end;
    end;
  end;

  if (idx < 0) or (idx >= DataCount) then
    Exit;

  { Remove DATA block }
  RemovedBlock := Blocks.level[0].Data[idx];

  Delete(Blocks.level[0].Data, idx, 1);
  Dec(Blocks.level[0].Count);

  SetLength(Result, 1);
  Result[0] := RemovedBlock;

  DataCount := Blocks.level[0].Count;

  { Determine new tree depth }
  NewTop := RequiredTop(DataCount);
  if NewTop < 0 then
    NewTop := 0;

  { Required index counts for new tree depth }
  if NewTop >= 1 then
    NewL1Count := RequiredLevel1(DataCount)
  else
    NewL1Count := 0;

  if NewTop >= 2 then
    NewL2Count := RequiredLevel2(NewL1Count)
  else
    NewL2Count := 0;

  { Release excess L1 blocks }
  while Blocks.level[1].Count > NewL1Count do
  begin
    Dec(Blocks.level[1].Count);
    RemovedBlock := Blocks.level[1].Data[Blocks.level[1].Count];

    SetLength(Blocks.level[1].Data, Blocks.level[1].Count);
    SetLength(Result, Length(Result) + 1);
    Result[High(Result)] := RemovedBlock;
  end;

  { Release excess L2 blocks }
  while Blocks.level[2].Count > NewL2Count do
  begin
    Dec(Blocks.level[2].Count);
    RemovedBlock := Blocks.level[2].Data[Blocks.level[2].Count];

    SetLength(Blocks.level[2].Data, Blocks.level[2].Count);
    SetLength(Result, Length(Result) + 1);
    Result[High(Result)] := RemovedBlock;
  end;

  Blocks.top := NewTop;
  fIsChanged := True;
end;

procedure TQNX6BlockManager.Flush;
var
  BitmapSize: QWord;
begin
  if not fIsChanged then
    Exit;

  if (fDevice = nil) or (fDevice.ActiveSB = nil) then
    Exit;

  BitmapSize := iceil(fDevice.ActiveSB.NumBlocks, 8);

  fDevice.DirectWrite := True;
  try
    SaveBlockData(
      fBitmapBlocks,
      fBitmap.BitsPtr,
      BitmapSize
      );
    fIsChanged := False;
  finally
    fDevice.DirectWrite := False;
  end;
end;

end.
