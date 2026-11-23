unit qnx6.compactor;

{$mode ObjFPC}{$H+}

interface

uses
  Classes,
  SysUtils,
  Math,
  {$IFDEF USEGENERICS}
  Generics.Collections,
  {$ELSE}
  lgHashMap,
  lgVector,
  {$ENDIF}
  bits,
  uMisc,
  CLI.Progress,
  CLI.Console,
  CLI.Interfaces,
  qnx6.device,
  qnx6.blockmgr,
  qnx6.inodemgr,
  qnx6.types,
  qnx6;

type
  { TQNX6Compactor }

  TQNX6Compactor = class
  private
    FFS: TQNX6Fs;
  public
    constructor Create(AFS: TQNX6Fs);

    function CompactBlocks: integer;
    function CompactInodes: integer;
  end;

implementation

constructor TQNX6Compactor.Create(AFS: TQNX6Fs);
begin
  inherited Create;
  FFS := AFS;
end;


function TQNX6Compactor.CompactBlocks: integer;
type
  {$IFDEF USEGENERICS}
  TDynArray = specialize TList<DWord>;
  TMap      = specialize TDictionary<DWord, DWord>;
  {$ELSE}
  TDynArray = specialize TGVector<DWord>;
  TMapType = specialize TGLiteHashMapLP<DWord, DWord, DWord>;
  TMap = TMapType.TMap;
  {$ENDIF}
var
  maxBlock, lu, ff: DWord;
  Buff: TBytes;
  BlocksMoved, i: integer;
  fromBlocks, toBlocks: TDynArray;
  spinner, progress: IProgressIndicator;
  FirstFreePos, LastUsedPos: DWord;

  function FirstFree: DWord;
  var
    pos: DWord;
  begin
    for pos := FirstFreePos to maxBlock - 1 do
      if not FFS.BlockMgr.Bitmap.Bits[pos] then
      begin
        FirstFreePos := pos + 1;
        Exit(pos);
      end;
    Result := maxBlock;
  end;

  function LastUsed: DWord;
  var
    pos: DWord;
  begin
    for pos := LastUsedPos downto FFS.Device.UserAreaStart do
      if FFS.BlockMgr.Bitmap.Bits[pos] then
      begin
        LastUsedPos := pos - 1;
        Exit(pos);
      end;
    Result := FFS.Device.UserAreaStart;
  end;

  procedure ReplaceInBlocksChains;
  var
    i, j, lvl: integer;
    v: DWord;
    Map: TMap;
    Blocks: TBlocksList;
    inodIdx: DWord;
    modified: boolean;
    {$IFDEF USEGENERICS}
    Pair: specialize TPair<DWord, TQNX6_DInode>;
    {$ELSE}
    Pair: TCachedDInodesType.TEntry;
    {$ENDIF}
  begin
    {$IFDEF USEGENERICS}
    Map := TMap.Create;
    {$ELSE}
    Map.Clear;
    {$ENDIF}
    try
      for i := 0 to fromBlocks.Count - 1 do
        Map.Add(fromBlocks[i], toBlocks[i]);

      for Pair in FFS.InodeMgr.CacheDInodes do
      begin
        inodIdx := Pair.Key;
        FFS.InodeMgr.LoadInodeBlocks(inodIdx, Blocks);
        modified := False;

        for lvl := 0 to Blocks.top do
          for j := 0 to Blocks.level[lvl].Count - 1 do
          begin
            if Map.TryGetValue(Blocks.level[lvl].Data[j], v) then
            begin
              Blocks.level[lvl].Data[j] := v;
              modified := True;
            end;
          end;

        if modified then
          FFS.InodeMgr.SaveInodeBlocks(inodIdx, Pair.Value.size, Blocks);
      end;

      modified := False;
      for lvl := 0 to FFS.InodeMgr.LongNameBlocks.top do
        for j := 0 to FFS.InodeMgr.LongNameBlocks.level[lvl].Count - 1 do
        begin
          if Map.TryGetValue(FFS.InodeMgr.LongNameBlocks.level[lvl].Data[j], v) then
          begin
            FFS.InodeMgr.LongNameBlocks.level[lvl].Data[j] := v;
            modified := True;
          end;
        end;

      if modified then
        FFS.InodeMgr.ChangedLong := True;

    finally
      {$IFDEF USEGENERICS}
      Map.Free;
      {$ELSE}
      Map.Clear;
      {$ENDIF}
    end;
  end;

begin
  Result := 0;
  if not FFS.InodeMgr.InodesLoaded then
    FFS.InodeMgr.PreloadInodes(True);

  if FFS.Device.BlockSize = 0 then Exit(0);

  maxBlock := Min(FFS.BlockMgr.Bitmap.Size, DWord(
    (FFS.Device.Stream.Size - FFS.Device.DataStart) div FFS.Device.BlockSize));

  if maxBlock <= FFS.Device.UserAreaStart then
    Exit(0);

  FirstFreePos := FFS.Device.UserAreaStart;
  LastUsedPos := maxBlock - 1;

  lu := LastUsed;
  ff := FirstFree;

  if lu <= ff then
  begin
    FFS.Device.Stream.Size := FFS.Device.DataStart + QWord(lu + 1) *
      FFS.Device.BlockSize;
    Exit(0);
  end;

  TConsole.WriteLn('Compacting blocks...');
  SetLength(Buff, FFS.Device.BlockSize);

  fromBlocks := TDynArray.Create;
  toBlocks := TDynArray.Create;

  try
    BlocksMoved := 0;

    spinner := CreateSpinner(ssDots);
    spinner.Start;

    while (lu > ff) do
    begin
      fromBlocks.Add(lu);
      toBlocks.Add(ff);
      Inc(BlocksMoved);

      if (BlocksMoved and $3FF) = 0 then
        spinner.Update(0);

      lu := LastUsed;
      ff := FirstFree;
    end;
    spinner.Stop;

    if BlocksMoved > 0 then
    begin
      ReplaceInBlocksChains;
      FFS.Device.DirectWrite := True;

      progress := CreateProgressBar(fromBlocks.Count, 50);
      progress.Start;

      for i := 0 to fromBlocks.Count - 1 do
      begin
        if (i and $3FF) = 0 then
          progress.Update(i);

        FFS.Device.ReadBlock(fromBlocks[i], @Buff[0]);
        FFS.Device.WriteBlock(toBlocks[i], @Buff[0]);

        FFS.BlockMgr.Bitmap.Bits[fromBlocks[i]] := False;
        FFS.BlockMgr.Bitmap.Bits[toBlocks[i]] := True;
      end;

      progress.Stop;
      FFS.Device.DirectWrite := False;
      Result := BlocksMoved;

      FFS.InodeMgr.Flush;
      FFS.BlockMgr.Flush;
      FFS.Device.Flush;
      FFS.Device.Stream.Size :=
        FFS.Device.DataStart + QWord(ff + 1) * FFS.Device.BlockSize;
    end;
  finally
    fromBlocks.Free;
    toBlocks.Free;
  end;
end;

function TQNX6Compactor.CompactInodes: integer;
type
  {$IFDEF USEGENERICS}
  TInodeRemap = specialize TDictionary<DWord, DWord>;
  {$ELSE}
  TInodeRemapType = specialize TGLiteHashMapLP<DWord, DWord, DWord>;
  TInodeRemap = TInodeRemapType.TMap;
  {$ENDIF}

  TInodeData = record
    OldIdx: DWord;
    NewIdx: DWord;
    Inode: TQNX6_DInode;
    Blocks: TBlocksList;
  end;
var
  i, j: integer;
  oldIdx, newIdx: DWord;
  dirEntries: TQNX6_ARawDirEntry;
  InodeRemap: TInodeRemap;
  totalUsed, entryIdx, maxInodes: DWord;
  progress: IProgressIndicator;
  changed: boolean;
  tempBuffer: array of TInodeData;
begin
  Result := 0;
  FFS.InodeMgr.PreloadInodes(True);

  maxInodes := FFS.Device.ActiveSB.NumInodes;
  totalUsed := FFS.InodeMgr.UsedInodesList.Count;
  if totalUsed = 0 then Exit(0);

  {$IFDEF USEGENERICS}
  InodeRemap := TInodeRemap.Create;
  {$ELSE}
  InodeRemap.Clear;
  {$ENDIF}

  try
    // 1. Формуємо карту мапінгу старий_індекс -> новий_індекс
    for newIdx := 1 to DWord(FFS.InodeMgr.UsedInodesList.Count) do
    begin
      oldIdx := FFS.InodeMgr.UsedInodesList[newIdx - 1];
      if oldIdx <> newIdx then
      begin
        {$IFDEF USEGENERICS}
        InodeRemap.Add(oldIdx, newIdx);
        {$ELSE}
        InodeRemap[oldIdx] := newIdx;
        {$ENDIF}
      end;
    end;

    if InodeRemap.Count = 0 then
      Exit(0);

    // 2. Оновлюємо посилання на inode у каталогах
    progress := CreateProgressBar(maxInodes, 50);
    progress.Start;

    for oldIdx := 1 to maxInodes do
    begin
      progress.Update(oldIdx);

      if not FFS.InodeMgr.InodeUsed(oldIdx) then Continue;
      if (FFS.InodeMgr.Inodes[oldIdx].mode and S_IFMT) <> S_IFDIR then Continue;

      FFS.ReadDirectory(oldIdx, dirEntries);
      changed := False;

      for j := 0 to High(dirEntries) do
      begin
        if dirEntries[j].inode <= 0 then Continue;

        if InodeRemap.TryGetValue(dirEntries[j].inode, entryIdx) then
        begin
          dirEntries[j].inode := entryIdx;
          changed := True;
          Inc(Result);
        end;
      end;

      if changed then
        FFS.WriteDirectory(oldIdx, dirEntries);
    end;
    progress.Stop;

    // 3. Зчитуємо всі inode та їхні карти блоків у тимчасовий буфер ДО запису
    SetLength(tempBuffer, InodeRemap.Count);
    i := 0;
    for oldIdx in InodeRemap.Keys do
    begin
      if InodeRemap.TryGetValue(oldIdx, newIdx) then
      begin
        tempBuffer[i].OldIdx := oldIdx;
        tempBuffer[i].NewIdx := newIdx;
        tempBuffer[i].Inode := FFS.InodeMgr.GetInode(oldIdx);
        FFS.InodeMgr.LoadInodeBlocks(oldIdx, tempBuffer[i].Blocks);
        Inc(i);
      end;
    end;

    // 4. Очищаємо всі старі позиції за допомогою EraseInode
    for i := 0 to High(tempBuffer) do
      FFS.InodeMgr.EraseInode(tempBuffer[i].OldIdx);

    // 5. Записуємо inode на нові позиції
    for i := 0 to High(tempBuffer) do
    begin
      FFS.InodeMgr.SetInode(tempBuffer[i].NewIdx, tempBuffer[i].Inode);
      FFS.InodeMgr.SaveInodeBlocks(tempBuffer[i].NewIdx, tempBuffer[i].Inode.size,
        tempBuffer[i].Blocks);
    end;

    // 6. Оновлюємо список використаних inodes
    FFS.InodeMgr.UsedInodesList.Clear;
    for i := 1 to totalUsed do
      FFS.InodeMgr.UsedInodesList.Add(i);

    FFS.InodeMgr.Flush;
    FFS.BlockMgr.Flush;
    FFS.Device.Flush;

  finally
    {$IFDEF USEGENERICS}
    InodeRemap.Free;
    {$ELSE}
    InodeRemap.Clear;
    {$ENDIF}
    SetLength(tempBuffer, 0);
  end;
end;


end.
