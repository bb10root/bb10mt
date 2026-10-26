unit fuseqnx6;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils;

procedure QNX6Mount(fileName, mountpoint: string; fg: boolean = False;
  dbg: boolean = False);

implementation

uses BaseUnix, fuse, qnx6, Math, qnx6.types;

var
  FS: TQNX6Fs;
  MP: string;

function qnx6_InodeStat(idx: integer): TStat;
var
  inode: TQNX6_DInode;
begin
  Result := Default(TStat);
  if idx > 0 then
  begin
    inode := FS.Inodes[idx];
    with Result do
    begin
      st_atime := inode.atime;
      st_ctime := inode.ctime;
      st_mtime := inode.mtime;
      st_gid := inode.gid;
      st_uid := inode.uid;
      st_mode := inode.mode;
      st_size := inode.size;
      st_nlink := inode.nlink;
    end;
  end;
end;

{ Get file attributes }
function qnx6_getattr(const aName: pchar; var aStat: TStat): cint; cdecl;
var
  idx: integer;
begin
  idx := FS.GetInodeByPath(aName);
  if idx > 0 then
  begin
    aStat := qnx6_InodeStat(idx);
    Result := 0;
  end
  else
    Result := -ESysENOENT;
end;

{ Read the target of a symbolic link }
function qnx6_readlink(const aName: pchar; aLinksToName: pchar;
  aLinksToNameSize: TSize): cint; cdecl;
var
  idx: integer;
  blk, s, c, q: dword;
  l: qword;
  Buff: array of byte;
begin
  idx := FS.GetInodeByPath(aName);
  if idx > 0 then
  begin
    if fpS_ISLNK(FS.Inodes[idx].mode) then
    begin
      q := Length(MP);
      blk := FS.Inodes[idx].blocks[0];
      l := FS.Inodes[idx].size;
      c := FS.BlockSize + q;
      SetLength(Buff, c);
      FillChar(Buff[0], c, 0);

      if q > 0 then
        Move(MP[1], Buff[0], q);

      FS.ReadBlock(blk, @Buff[q]);

      s := Min(aLinksToNameSize - 1, q + l);
      if s > 0 then
        Move(Buff[0], aLinksToName^, s);

      aLinksToName[s] := #0;
      Result := 0;
    end
    else
      Result := -ESysENOLINK;
  end
  else
    Result := -ESysENOENT;
end;

{ Create a file node }
function qnx6_mknod(const aName: pchar; aMode: TMode; aDevice: TDev): cint; cdecl;
begin
  Result := 0;
end;

{ Create a directory }
function qnx6_mkdir(const aDirectoryName: pchar; aMode: TMode): cint; cdecl;
begin
  Result := FS.MkDir(aDirectoryName, S_IFDIR or aMode);
  if Result > 0 then Result := 0;
end;

{ Remove a file }
function qnx6_unlink(const aName: pchar): cint; cdecl;
begin
  Result := FS.removeFileDir(aName, False);
end;

{ Remove a directory }
function qnx6_rmdir(const aName: pchar): cint; cdecl;
begin
  Result := FS.removeFileDir(aName, True);
end;

{ Create a symbolic link }
function qnx6_symlink(const aLinksToName, aName: pchar): cint; cdecl;
var
  s: string;
  l: integer;
begin
  s := ExpandFileName(aLinksToName);
  l := Length(MP);
  if (l > 0) and (Copy(s, 1, l) = MP) then
    Delete(s, 1, l);
  Result := FS.symlink(PChar(s), aName);
end;

{ Rename a file }
function qnx6_rename(const aName, aNewName: pchar): cint; cdecl;
begin
  Result := FS.Rename(aName, aNewName);
end;

{ Create a hard link to a file }
function qnx6_link(const aLinksToName, aName: pchar): cint; cdecl;
begin
  Result := FS.link(aLinksToName, aName);
end;

{ Change the permission bits of a file }
function qnx6_chmod(const aName: pchar; aMode: TMode): cint; cdecl;
var
  idx: integer;
  inode: TQNX6_DInode;
begin
  idx := FS.GetInodeByPath(aName);
  if idx > 0 then
  begin
    inode := FS.Inodes[idx];
    inode.mode := aMode;
    FS.Inodes[idx] := inode;
    Result := 0;
  end
  else
    Result := -ESysENOENT;
end;

{ Change the owner and group of a file }
function qnx6_chown(const aName: pchar; aUID: TUid; aGID: TGid): cint; cdecl;
var
  idx: integer;
  inode: TQNX6_DInode;
begin
  idx := FS.GetInodeByPath(aName);
  if idx > 0 then
  begin
    inode := FS.Inodes[idx];
    inode.uid := aUID;
    inode.gid := aGID;
    FS.Inodes[idx] := inode;
    Result := 0;
  end
  else
    Result := -ESysENOENT;
end;

{ Change the size of a file }
function qnx6_truncate(const aName: pchar; aNewSize: TOff): cint; cdecl;
var
  idx: integer;
begin
  idx := FS.GetInodeByPath(aName);
  if idx < 1 then
    Result := -ESysENOENT
  else
    Result := FS.SetSize(idx, aNewSize);
end;

{ File open operation }
function qnx6_open(const aName: pchar; aFileInfo: PFuseFileInfo): cint; cdecl;
var
  idx: integer;
begin
  idx := FS.GetInodeByPath(aName);
  if idx < 1 then
    Result := -ESysENOENT
  else
    Result := 0;
end;

{ Read data from an open file }
function qnx6_read(const aName: pchar; aBuffer: pointer; aBufferSize: TSize;
  aFileOffset: TOff; aFileInfo: PFuseFileInfo): cint; cdecl;
var
  idx, c, i, i1, i2, numBlocks: integer;
  Buff: array of byte;
  Blocks: TBlocksList;
  fsize: qword;
begin
  idx := FS.GetInodeByPath(aName);
  if idx < 1 then
    Exit(-ESysENOENT);

  fsize := FS.Inodes[idx].size;
  if aFileOffset >= fsize then
    Exit(0);

  FS.InodeMgr.LoadInodeBlocks(idx, Blocks);

  i1 := aFileOffset div FS.BlockSize;
  i2 := (aFileOffset + aBufferSize - 1) div FS.BlockSize + 1;
  numBlocks := i2 - i1;

  SetLength(Buff, numBlocks * FS.BlockSize);
  FillChar(Buff[0], Length(Buff), 0);

  for i := 0 to numBlocks - 1 do
  begin
    if (i1 + i) < Blocks.level[0].Count then
      FS.ReadBlock(Blocks.level[0].Data[i1 + i], @Buff[i * FS.BlockSize]);
  end;

  c := Min(int64(aBufferSize), int64(fsize - aFileOffset));
  if c > 0 then
    Move(Buff[aFileOffset mod FS.BlockSize], aBuffer^, c);

  Result := c;
end;

{ Write data to an open file }
function qnx6_write(const aName: pchar; const aBuffer: Pointer;
  aBufferSize: TSize; aFileOffset: TOff; aFileInfo: PFuseFileInfo): cint; cdecl;
var
  idx, c, i, i1, i2, numBlocks: integer;
  Buff: array of byte;
  Blocks: TBlocksList;
  fsize: qword;
begin
  idx := FS.GetInodeByPath(aName);
  if idx < 1 then
    Exit(-ESysENOENT);

  fsize := FS.Inodes[idx].size;
  if (aFileOffset + aBufferSize) > fsize then
  begin
    Result := FS.SetSize(idx, aFileOffset + aBufferSize);
    if Result < 0 then Exit;
    fsize := aFileOffset + aBufferSize;
  end;

  FS.InodeMgr.LoadInodeBlocks(idx, Blocks);

  i1 := aFileOffset div FS.BlockSize;
  i2 := (aFileOffset + aBufferSize - 1) div FS.BlockSize + 1;
  numBlocks := i2 - i1;

  SetLength(Buff, numBlocks * FS.BlockSize);
  FillChar(Buff[0], Length(Buff), 0);

  for i := 0 to numBlocks - 1 do
  begin
    if (i1 + i) < Blocks.level[0].Count then
      FS.ReadBlock(Blocks.level[0].Data[i1 + i], @Buff[i * FS.BlockSize]);
  end;

  c := Min(int64(aBufferSize), int64(fsize - aFileOffset));
  if c > 0 then
    Move(aBuffer^, Buff[aFileOffset mod FS.BlockSize], c);

  for i := 0 to numBlocks - 1 do
  begin
    if (i1 + i) < Blocks.level[0].Count then
      FS.WriteBlock(Blocks.level[0].Data[i1 + i], @Buff[i * FS.BlockSize]);
  end;

  Result := c;
end;

{ Get file system statistics }
function qnx6_statfs(const aName: pchar; aStatVFS: PStatVFS): cint; cdecl;
begin
  aStatVFS^.f_bsize := FS.BlockSize;
  aStatVFS^.f_frsize := FS.BlockSize;
  aStatVFS^.f_blocks := FS.GetBlockCount;
  aStatVFS^.f_bfree := FS.GetFreeBlockCount;
  aStatVFS^.f_bavail := FS.GetFreeBlockCount;

  aStatVFS^.f_files := FS.GetInodeCount;
  aStatVFS^.f_ffree := FS.GetFreeInodeCount;
  aStatVFS^.f_favail := FS.GetFreeInodeCount;
  aStatVFS^.f_namemax := 510;
  Result := 0;
end;

{ Flush cached data }
function qnx6_flush(const aName: pchar; aFileInfo: PFuseFileInfo): cint; cdecl;
begin
  FS.Flush;
  Result := 0;
end;

{ Release an open file }
function qnx6_release(const aName: pchar; aFileInfo: PFuseFileInfo): cint; cdecl;
begin
  Result := 0;
end;

{ Synchronize file contents }
function qnx6_fsync(const aName: pchar; aDataSync: cint;
  aFileInfo: PFuseFileInfo): cint; cdecl;
begin
  FS.Flush;
  Result := 0;
end;

{ Extended Attributes Stubs }
function qnx6_setxattr(const aName, aKey, aValue: pchar; aValueSize: TSize;
  Flags: cint): cint; cdecl;
begin
  Result := 0;
end;

function qnx6_getxattr(const aName, aKey: pchar; aValue: pchar;
  aValueSize: TSize): cint; cdecl;
begin
  Result := 0;
end;

function qnx6_listxattr(const aName: pchar; aList: pchar; aListSize: TSize): cint; cdecl;
begin
  Result := 0;
end;

function qnx6_removexattr(const aName, aKey: pchar): cint; cdecl;
begin
  Result := 0;
end;

{ Open directory }
function qnx6_opendir(const aName: pchar; aFileInfo: PFuseFileInfo): cint; cdecl;
begin
  Result := 0;
end;

{ Read directory }
function qnx6_readdir(const aName: pchar; aBuffer: pointer;
  aFillDirFunc: TFuseFillDir; aFileOffset: TOff; aFileInfo: PFuseFileInfo): cint; cdecl;
var
  i, c: integer;
  DE: TQNX6_ARawDirEntry;
  stat: TStat;
  bName: string;
begin
  c := FS.ReadDirectory(aName, DE);
  if c < 1 then
    Exit(-ESysENOENT);

  for i := 0 to c - 1 do
  begin
    if DE[i].inode > 0 then
    begin
      stat := qnx6_InodeStat(DE[i].inode);
      bName := FS.RawDirEntryGetName(DE[i]);
      if (bName <> '') and (aFillDirFunc(aBuffer, PChar(bName), @stat, 0) <> 0) then
        Exit(-ESysENOMEM);
    end;
  end;
  Result := 0;
end;

{ Release directory }
function qnx6_releasedir(const aName: pchar; aFileInfo: PFuseFileInfo): cint; cdecl;
begin
  Result := 0;
end;

{ Synchronize directory contents }
function qnx6_fsyncdir(const aName: pchar; aDataSync: integer;
  aFileInfo: PFuseFileInfo): cint; cdecl;
begin
  FS.Flush;
  Result := 0;
end;

{ Initialize filesystem }
function qnx6_init(var aConnectionInfo: TFuseConnInfo): pointer; cdecl;
begin
  Result := nil;
end;

{ Clean up filesystem }
procedure qnx6_destroy(aUserData: pointer); cdecl;
begin
  if Assigned(FS) then
    FS.Flush;
end;

{ Check file access permissions }
function qnx6_access(const aName: pchar; aMode: cint): cint; cdecl;
begin
  Result := 0;
end;

{ Create and open a file }
function qnx6_create(const aName: pchar; aMode: TMode;
  aFileInfo: PFuseFileInfo): cint; cdecl;
begin
  Result := FS.CreateFile(aName, aMode);
  if Result > 0 then Result := 0;
end;

{ Change the size of an open file }
function qnx6_ftruncate(const aName: pchar; aSize: TOff;
  aFileInfo: PFuseFileInfo): cint; cdecl;
begin
  Result := 0;
end;

{ Get attributes from an open file }
function qnx6_fgetattr(const aName: pchar; aOutStat: PStat;
  PFileInfo: PFuseFileInfo): cint; cdecl;
begin
  Result := 0;
end;

{ Perform POSIX file locking operation }
function qnx6_lock(const aName: pchar; aFileInfo: PFuseFileInfo;
  aCMD: cint; var aLock: FLock): cint; cdecl;
begin
  Result := 0;
end;

{ Change access and modification times }
function qnx6_utimens(const aName: pchar; const aTime: TFuseTimeTuple): cint; cdecl;
var
  idx: integer;
  inode: TQNX6_DInode;
begin
  idx := FS.GetInodeByPath(aName);
  if idx > 0 then
  begin
    inode := FS.Inodes[idx];
    inode.atime := aTime[0].tv_sec;
    inode.mtime := aTime[1].tv_sec;
    FS.Inodes[idx] := inode;
    Result := 0;
  end
  else
    Result := -ESysENOENT;
end;

var
  qnx6_oper: TFuseOperations;

procedure QNX6Mount(fileName, mountpoint: string; fg: boolean = False;
  dbg: boolean = False);
var
  fStream: TFileStream;
  _argv: array of pchar;
  res, argIdx: integer;
begin
  MP := ExpandFileName(mountpoint);

  SetLength(_argv, 4);
  _argv[0] := PChar(fileName);
  _argv[1] := PChar(MP);
  _argv[2] := PChar('-ofsname=qnx6');
  _argv[3] := PChar('-s');

  if fg then
  begin
    argIdx := Length(_argv);
    SetLength(_argv, argIdx + 1);
    _argv[argIdx] := PChar('-f');
  end;

  if dbg then
  begin
    argIdx := Length(_argv);
    SetLength(_argv, argIdx + 1);
    _argv[argIdx] := PChar('-d');
  end;

  if FileExists(fileName) then
  begin
    fStream := TFileStream.Create(fileName, fmOpenReadWrite);
    try
      FS := TQNX6Fs.Create(fStream);
      try
        FS.Open;

        qnx6_oper := Default(TFuseOperations);
        with qnx6_oper do
        begin
          Open := @qnx6_open;
          getattr := @qnx6_getattr;
          readdir := @qnx6_readdir;
          Read := @qnx6_read;
          Write := @qnx6_write;
          truncate := @qnx6_truncate;
          chmod := @qnx6_chmod;
          chown := @qnx6_chown;
          unlink := @qnx6_unlink;
          link := @qnx6_link;
          rmdir := @qnx6_rmdir;
          readlink := @qnx6_readlink;
          symlink := @qnx6_symlink;
          Create := @qnx6_create;
          mkdir := @qnx6_mkdir;
          rename := @qnx6_rename;
          utimens := @qnx6_utimens;
          statfs := @qnx6_statfs;
          Destroy := @qnx6_destroy;
        end;

        res := fuse_main(Length(_argv), @_argv[0], @qnx6_oper, SizeOf(qnx6_oper), nil);
      finally
        FreeAndNil(FS);
      end;
    finally
      FreeAndNil(fStream);
    end;
  end;
end;

end.
