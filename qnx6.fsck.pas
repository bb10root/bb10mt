unit qnx6.fsck;

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
  bits,
  uMisc,
  CLI.Console,
  qnx6.device,
  qnx6.blockmgr,
  qnx6.inodemgr,
  qnx6.types,
  qnx6;

type
  { TQNX6Fsck }

  TQNX6Fsck = class
  private
    FFS: TQNX6Fs;
  public
    constructor Create(AFS: TQNX6Fs);
    procedure Execute(var Errors: TStringList; Fix: boolean = False);
  end;

implementation

constructor TQNX6Fsck.Create(AFS: TQNX6Fs);
begin
  inherited Create;
  FFS := AFS;
end;

procedure TQNX6Fsck.Execute(var Errors: TStringList; Fix: boolean = False);
type
  {$IFDEF USEGENERICS}
  TCache = specialize TDictionary<DWord, Integer>;
  {$ELSE}
  TCacheType = specialize TGLiteHashMapLP<DWord, integer, DWord>;
  TCache = TCacheType.TMap;
  {$ENDIF}
var
  i, j, lvl: DWord;
  target, Inode: TQNX6_DInode;
  Blocks: TBlocksList;
  DE: TQNX6_ARawDirEntry;
  seenBlocks, claimedBlocks: TBits;
  blk: DWord;
  usedLinks: TCache;
  toEraseInodes: array of DWord;
  eraseCount: integer;
  actualNlink, currentCount: integer;
  Name: utf8string;
  HasDot, HasDotDot: boolean;
  TotalFileSize, ImageSize: int64;
  {$IFDEF DEBUGFSCK}
  testBuff: array of byte;
  testStream: TFileStream;
  {$ENDIF}
begin
  if not Assigned(Errors) then
    Errors := TStringList.Create;

  seenBlocks := TBits.Create(FFS.BlockMgr.Bitmap.Size);
  claimedBlocks := TBits.Create(FFS.BlockMgr.Bitmap.Size);

  {$IFDEF USEGENERICS}
  usedLinks := TCache.Create;
  {$ELSE}
  usedLinks.Clear;
  {$ENDIF}

  TotalFileSize := 0;
  eraseCount := 0;
  SetLength(toEraseInodes, 0);

  try
    if (not Assigned(FFS.Device.ActiveSB)) or (not FFS.Device.ActiveSB.isValid) then
      raise Exception.Create('Filesystem not initialized or invalid superblock');

    FFS.InodeMgr.PreloadInodes(True);

    TConsole.WriteLn('-> Checking inodes');
    for i in FFS.InodeMgr.UsedInodesList do
    begin
      Inode := FFS.InodeMgr.GetInode(i);

      if Inode.mode = 0 then
      begin
        Errors.Add(Format('Inode #%d has zero mode (uninitialized)', [i]));
        Continue;
      end;

      if Inode.size > FFS.Device.MaxBlocks * FFS.Device.BlockSize then
        Errors.Add(Format('Inode #%d: size too large (%d bytes)', [i, Inode.size]));

      Inc(TotalFileSize, Inode.size);

      // Зауваження: LoadInodeBlocks має повертати як блоки даних, так і
      // непрямі мета-блоки (Indirect Blocks), щоб уникнути їх хибного очищення у бітмапі.
      FFS.InodeMgr.LoadInodeBlocks(i, Blocks);
      for lvl := 0 to DWord(Blocks.top) do
        for blk in Blocks.level[lvl].Data do
        begin
          if (blk >= FFS.BlockMgr.Bitmap.Size) then
            Errors.Add(Format('Inode #%d references out-of-range block %d', [i, blk]))
          else if blk <> 0 then
          begin
            if seenBlocks[blk] then
              Errors.Add(Format('Duplicate block %d referenced by inode #%d', [blk, i]))
            else
              seenBlocks[blk] := True;

            claimedBlocks[blk] := True;
          end;
        end;
    end;

    TConsole.WriteLn('-> Processing longnames');
    FFS.InodeMgr.LoadLongNames;
    for lvl := 0 to DWord(FFS.InodeMgr.LongNameBlocks.top) do
      for blk in FFS.InodeMgr.LongNameBlocks.level[lvl].Data do
      begin
        if (blk >= FFS.BlockMgr.Bitmap.Size) then
          Errors.Add(Format('Inode #%d references out-of-range block %d', [i, blk]))
        else if blk <> 0 then
        begin
          if seenBlocks[blk] then
            Errors.Add(Format('Duplicate block %d referenced by inode #%d', [blk, i]))
          else
            seenBlocks[blk] := True;

          claimedBlocks[blk] := True;
        end;
      end;

    TConsole.WriteLn('-> Checking directories');
    for i in FFS.InodeMgr.UsedInodesList do
    begin
      Inode := FFS.InodeMgr.GetInode(i);
      if (Inode.mode and S_IFMT) = S_IFDIR then
      begin
        DE := nil;
        try
          if FFS.ReadDirectory(i, DE) < 0 then
          begin
            Errors.Add(Format('Failed to read directory at inode #%d', [i]));
            Continue;
          end;

          HasDot := False;
          HasDotDot := False;

          if (DE <> nil) then
            for j := 0 to High(DE) do
            begin
              Name := FFS.RawDirEntryGetName(DE[j]);
              if not FFS.InodeMgr.IsValidInode(DE[j].inode) then
                Errors.Add(Format(
                  'Directory inode #%d references invalid inode %d ("%s")',
                  [i, DE[j].inode, Name]))
              else
              begin
                if Name = '.' then HasDot := True;
                if Name = '..' then HasDotDot := True;

                if Copy(Name, 1, 8) = 'DAMAGED ' then
                  Errors.Add(Format(
                    'Directory #%d contains entry "%s" pointing to unallocated inode %d',
                    [
                    i, Name, DE[j].inode]))
                else if not FFS.InodeMgr.UsedInodesList.Contains(DE[j].inode) then
                  Errors.Add(Format(
                    'Directory #%d contains entry "%s" pointing to unallocated inode %d',
                    [
                    i, Name, DE[j].inode]))
                else
                begin
                  target := FFS.InodeMgr.GetInode(DE[j].inode);
                  if target.mode = 0 then
                    Errors.Add(
                      Format('Directory #%d entry "%s" points to cleared inode #%d (mode = 0)',
                      [i, Name, DE[j].inode]));

                  if (Name = '.') and (DE[j].inode <> i) then
                    Errors.Add(
                      Format('Directory #%d: "." entry points to inode #%d instead of self',
                      [i, DE[j].inode]));

                  if (Name = '..') and (i = 1) and (DE[j].inode <> 1) then
                    Errors.Add(
                      Format('Root directory ".." must point to itself (inode 1), got %d',
                      [DE[j].inode]));
                end;
              end;

              // Облік кількості посилань
              if usedLinks.TryGetValue(DE[j].inode, currentCount) then
                usedLinks.AddOrSetValue(DE[j].inode, currentCount + 1)
              else
                usedLinks.Add(DE[j].inode, 1);
            end;

          if not HasDot then Errors.Add(Format('Directory #%d missing "." entry', [i]));
          if not HasDotDot then
            Errors.Add(Format('Directory #%d missing ".." entry', [i]));
        finally
          // Звільнення динамічного масиву записів каталогу (запобігає витоку RAM)
          SetLength(DE, 0);
        end;
      end;
    end;

    TConsole.WriteLn('-> Checking link counts');
    for i in FFS.InodeMgr.UsedInodesList do
    begin
      Inode := FFS.InodeMgr.GetInode(i);

      if usedLinks.TryGetValue(i, actualNlink) then
      begin
        if Inode.nlink <> actualNlink then
        begin
          Errors.Add(Format('Inode #%d: nlink=%d, actual references=%d',
            [i, Inode.nlink, actualNlink]));
          if Fix then
          begin
            Inode.nlink := actualNlink;
            FFS.InodeMgr.SetInode(i, Inode);
          end;
        end;
      end
      else if Inode.nlink > 0 then
      begin
        Errors.Add(Format('Inode #%d: has nlink=%d but no directory references (orphan)',
          [i, Inode.nlink]));
        if Fix then
        begin
          if eraseCount >= Length(toEraseInodes) then
            SetLength(toEraseInodes, (eraseCount + 1) * 2);
          toEraseInodes[eraseCount] := i;
          Inc(eraseCount);
        end;
      end;
    end;

    // Безпечне видалення орфанних інодів за межами циклу ітерації
    if Fix and (eraseCount > 0) then
    begin
      SetLength(toEraseInodes, eraseCount);
      for i in toEraseInodes do
        FFS.InodeMgr.EraseInode(i);
    end;

    {$IFDEF DEBUGFSCK}
    SetLength(testBuff, FFS.Device.BlockSize);
    {$ENDIF}

    TConsole.WriteLn('-> Checking bitmap consistency');
    for i := FFS.Device.UserAreaStart to FFS.BlockMgr.Bitmap.Size - 1 do
    begin
      if FFS.BlockMgr.Bitmap.Bits[i] and (not claimedBlocks[i]) then
      begin
        Errors.Add(Format(
          'Block %d is marked used in bitmap but not referenced by any inode', [i]));
        if Fix then FFS.BlockMgr.Bitmap.Clear(i);
      end;

      if (not FFS.BlockMgr.Bitmap.Bits[i]) and claimedBlocks[i] then
      begin
        {$IFDEF DEBUGFSCK}
        testStream := TFileStream.Create(Format('block_%d.bin', [i]), fmCreate);
        try
          FFS.Device.ReadBlock(i, @testBuff[0]);
          testStream.WriteBuffer(testBuff[0], FFS.Device.BlockSize);
        finally
          FreeAndNil(testStream);
        end;
        {$ENDIF}

        Errors.Add(Format(
          'Block %d is referenced by inodes but not marked used in bitmap',
          [i]));
        if Fix then FFS.BlockMgr.Bitmap.SetOn(i);
      end;
    end;

    ImageSize := FFS.Device.Stream.Size;
    TConsole.WriteLn(Format('-> Total file data size: %.2f MB',
      [TotalFileSize / (1024 * 1024)]));
    TConsole.WriteLn(Format('-> Image file size: %.2f MB', [ImageSize / (1024 * 1024)]));

    if Fix and (Errors.Count > 0) then
    begin
      FFS.BlockMgr.IsChanged := True;
      FFS.InodeMgr.Flush;
      FFS.BlockMgr.Flush;
      FFS.Device.Flush;
    end;

  finally
    seenBlocks.Free;
    claimedBlocks.Free;
    {$IFDEF USEGENERICS}
    usedLinks.Free;
    {$ELSE}
    usedLinks.Clear;
    {$ENDIF}
  end;
end;

end.
