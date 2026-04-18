unit fuseqnx6;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils;

procedure QNX6Mount(fileName, mountpoint: string; fg: boolean = False; dbg: boolean = False);


implementation

uses BaseUnix, fuse, qnx6, Math;

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

{ Get file attributes.

  Similar to stat(). The 'st_dev' and 'st_blksize' fields are ignored.
  The 'st_ino' field is ignored except if the 'use_ino' mount option is given.
}
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


{ Read the target of a symbolic link

  The buffer should be filled with a null terminated string. The buffer size
  argument includes the space for the terminating null character. If the
  linkname is too long to fit in the buffer, it should be truncated.
  The return value should be 0 for success.
}
function qnx6_readlink(const aName: pchar; aLinksToName: pchar; aLinksToNameSize: TSize): cint; cdecl;
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
      move(MP[1], buff[0], q);
      FS.ReadBlock(blk, @buff[q]);
      s := min(aLinksToNameSize - 1, q + l);
      move(buff[0], aLinksToName^, s);
      aLinksToName[s] := #0;

      Result := 0;
    end
    else
      Result := -ESysENOLINK;
  end
  else
    Result := -ESysENOENT;

end;


{ Create a file node

  This is called for creation of all non-directory, non-symlink nodes.If the
  filesystem defines a create() method, then for regular files that will be
  called instead
}
function qnx6_mknod(const aName: pchar; aMode: TMode; aDevice: TDev): cint; cdecl;
begin

end;

{ Create a directory

  Note that the mode argument may not have the type specification bits set,
  i.e. S_ISDIR(mode) can be false. To obtain the correct directory type bits
  use  mode|S_IFDIR
}
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
  s: utf8string;
  c, l: integer;
begin
  s := ExpandFileName(aLinksToName);
  l := length(MP);
  if Copy(s, 1, l) = MP then
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
  begin
    Result := FS.SetSize(idx, aNewSize);

  end;

end;

{ File open operation

  No creation (O_CREAT, O_EXCL) and by default also no truncation (O_TRUNC)
  flags will be passed to open(). If an application specifies O_TRUNC, fuse
  first calls truncate() and then open(). Only if 'atomic_o_trunc' has been
  specified and kernel version is 2.6.24 or later, O_TRUNC is passed on to
  open.

  Unless the 'default_permissions' mount option is given, open should check
  if the operation is permitted for the given flags. Optionally open may
  also return an arbitrary filehandle in the fuse_file_info structure, which
  will be passed to all file operations.

  Changed in version 2.2
}
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

{ Read data from an open file

  Read should return exactly the number of bytes requested except on EOF or
  error, otherwise the rest of the data will be substituted with zeroes. An
  exception to this is when the 'direct_io' mount option is specified, in
  which case the return value of the read system call will reflect the
  return value of this operation.

  Changed in version 2.2
}
function qnx6_read(const aName: pchar; aBuffer: pointer; aBufferSize: TSize;
  aFileOffset: TOff; aFileInfo: PFuseFileInfo): cint; cdecl;
var
  idx, s, c, i, i1, i2: integer;
  buff: array of byte;
  Blocks: TBlocksList;
  fsize: qword;
begin
  idx := FS.GetInodeByPath(aName);
  if idx < 1 then
    Result := -ESysENOENT
  else
  begin
    fsize := FS.Inodes[idx].size;
    if aFileOffset >= fsize then
    begin
      Result := 0;
      exit;
    end;

    FS.LoadInodeBlocks(idx, Blocks);
    i1 := aFileOffset div FS.BlockSize;
    i2 := (aFileOffset + aBufferSize) div FS.BlockSize;
    if (aFileOffset + aBufferSize) and (FS.BlockSize - 1) <> 0 then
      Inc(i2);

    SetLength(Buff, ((i2 - i1)) * FS.BlockSize);

    for i := i1 to pred(i2) do
      FS.ReadBlock(Blocks.level[0].Data[i], @Buff[(i - i1) * FS.BlockSize]);

    c := min(int64(aBufferSize), int64(fsize - aFileOffset));
    move((@buff[aFileOffset mod FS.BlockSize])^, aBuffer^, c);
    Result := c;
  end;
end;

{ Write data to an open file

  Write should return exactly the number of bytes requested except on error.
  An exception to this is when the 'direct_io' mount option is specified
  (see read operation).

  Changed in version 2.2
}
function qnx6_write(const aName: pchar; const aBuffer: Pointer; aBufferSize: TSize;
  aFileOffset: TOff; aFileInfo: PFuseFileInfo): cint; cdecl;
var
  idx, s, c, i, i1, i2: integer;
  buff: array of byte;
  Blocks: TBlocksList;
  fsize: qword;
begin
  idx := FS.GetInodeByPath(aName);
  if idx < 1 then
    Result := -ESysENOENT
  else
  begin

    fsize := FS.Inodes[idx].size;
    if aFileOffset + aBufferSize >= fsize then
    begin
      // Enlarge file
      Result := FS.SetSize(idx, aFileOffset + aBufferSize);

      if Result < 0 then exit;
      fsize := aFileOffset + aBufferSize;
    end;

    FS.LoadInodeBlocks(idx, Blocks);

    i1 := aFileOffset div FS.BlockSize;
    i2 := (aFileOffset + aBufferSize) div FS.BlockSize;
    if (aFileOffset + aBufferSize) and (FS.BlockSize - 1) <> 0 then
      Inc(i2);

    SetLength(Buff, ((i2 - i1)) * FS.BlockSize);

    if Blocks.level[0].Count > 0 then
      for i := i1 to pred(i2) do
        FS.ReadBlock(Blocks.level[0].Data[i], @Buff[(i - i1) * FS.BlockSize]);

    c := min(int64(aBufferSize), int64(fsize - aFileOffset));
    move(aBuffer^, (@buff[aFileOffset mod FS.BlockSize])^, c);

    for i := i1 to pred(i2) do
      FS.WriteBlock(Blocks.level[0].Data[i], @Buff[(i - i1) * FS.BlockSize]);

    Result := c;
  end;

end;

{ Get file system statistics

  The 'f_frsize', 'f_favail', 'f_fsid' and 'f_flag' fields are ignored

  Replaced 'struct statfs' parameter with 'struct statvfs' in version 2.5
}
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

{ Possibly flush cached data

  BIG NOTE: This is not equivalent to fsync(). It's not a request to sync
  dirty data.

  Flush is called on each close() of a file descriptor. So if a filesystem
  wants to return write errors in close() and the file has cached dirty
  data, this is a good place to write back data and return any errors. Since
  many applications ignore close() errors this is not always useful.

  NOTE: The flush() method may be called more than once for each open().
  This happens if more than one file descriptor refers to an opened file due
  to dup(), dup2() or fork() calls. It is not possible to determine if a
  flush is final, so each flush should be treated equally.  Multiple
  write-flush sequences are relatively rare, so this shouldn't be a problem.

  Filesystems shouldn't assume that flush will always be called after some
  writes, or that if will be called at all.

  Changed in version 2.2
}
function qnx6_flush(const aName: pchar; aFileInfo: PFuseFileInfo): cint; cdecl;
begin
  FS.Flush;
  Result := 0;
end;

{ Release an open file

  Release is called when there are no more references to an open file: all
  file descriptors are closed and all memory mappings are unmapped.

  For every open() call there will be exactly one release() call with the
  same flags and file descriptor. It is possible to have a file opened more
  than once, in which case only the last release will mean, that no more
  reads/writes will happen on the file. The return value of release is
  ignored.

  Changed in version 2.2
}
function qnx6_release(const aName: pchar; aFileInfo: PFuseFileInfo): cint; cdecl;
begin

end;

{ Synchronize file contents

  If the datasync parameter is non-zero, then only the user data should be
  flushed, not the meta data.

  Changed in version 2.2
}
function qnx6_fsync(const aName: pchar; aDataSync: cint; aFileInfo: PFuseFileInfo): cint; cdecl;
begin
  FS.Flush;
  Result := 0;
end;

{ Set Extended Attributes }
function qnx6_setxattr(const aName, aKey, aValue: pchar; aValueSize: TSize; Flags: cint): cint; cdecl;
begin

end;

{ Get Extended Attributes }
function qnx6_getxattr(const aName, aKey: pchar; aValue: pchar; aValueSize: TSize): cint; cdecl;
begin

end;

{ List Extended Attributes }
function qnx6_listxattr(const aName: pchar; aList: pchar; aListSize: TSize): cint; cdecl;
begin

end;

{ Remove Extended Attributes }
function qnx6_removexattr(const aName, aKey: pchar): cint; cdecl;
begin

end;

{ Open directory

  Unless the 'default_permissions' mount option is given, this method should
  check if opendir is permitted for this directory. Optionally opendir may
  also return an arbitrary filehandle in the fuse_file_info structure, which
  will be passed to readdir, closedir and fsyncdir.

  Introduced in version 2.3
}
function qnx6_opendir(const aName: pchar; aFileInfo: PFuseFileInfo): cint; cdecl;
begin

end;


{ Read directory

  This supersedes the old getdir() interface. New applications should use
  this.

  The filesystem may choose between two modes of operation:

  1) The readdir implementation ignores the offset parameter, and passes
  zero to the filler function's offset.  The filler function will not
  return '1' (unless an error happens), so the whole directory is read in a
  single readdir operation.  This works just like the old getdir() method.

  2) The readdir implementation keeps track of the offsets of the directory
  entries. It uses the offset parameter and always passes non-zero offset to
  the filler function. When the buffer is full (or an error happens) the
  filler function will return '1'.

  Introduced in version 2.3
}
function qnx6_readdir(const aName: pchar; aBuffer: pointer; aFillDirFunc: TFuseFillDir;
  aFileOffset: TOff; aFileInfo: PFuseFileInfo): cint; cdecl;
var
  i, c, idx: integer;
  DE: TQNX6_ARawDirEntry;
  stat: TStat;
  bName: string;
begin
  c := FS.ReadDirectory(aName, DE);
  if c < 1 then
  begin
    Result := -ESysENOENT;
    exit;
  end;

  for i := 0 to pred(c) do
  begin
    if DE[i].inode > 0 then
    begin
      stat := qnx6_InodeStat(DE[i].inode);
      bName := FS.RawDirEntryGetName(DE[i]);
      if aFillDirFunc(aBuffer, @bName[1], @stat, 0) <> 0 then
        raise EHeapException.Create('filler error');
    end;
  end;
  Result := 0;
end;

{ Release directory

  Introduced in version 2.3
}
function qnx6_releasedir(const aName: pchar; aFileInfo: PFuseFileInfo): cint; cdecl;
begin

end;

{ Synchronize directory contents

  If the datasync parameter is non-zero, then only the user data should be
  flushed, not the meta data

  Introduced in version 2.3
}
function qnx6_fsyncdir(const aName: pchar; aDataSync: integer; aFileInfo: PFuseFileInfo): cint; cdecl;
begin
  FS.Flush;
  Result := 0;
end;

{ Initialize filesystem

  The return value will passed in the private_data field of fuse_context to
  all file operations and as a parameter to the destroy() method.

  Introduced in version 2.3
  Changed in version 2.6
}
function qnx6_init(var aConnectionInfo: TFuseConnInfo): pointer; cdecl;
begin

end;

{ Clean up filesystem

  Called on filesystem exit.

  Introduced in version 2.3
}
procedure qnx6_destroy(aUserData: pointer); cdecl;
begin
  FS.Flush;
end;

{ Check file access permissions

  This will be called for the access() system call. If the
  'default_permissions' mount option is given, this method is not called.

  This method is not called under Linux kernel versions 2.4.x

  Introduced in version 2.5
}
function qnx6_access(const aName: pchar; aMode: cint): cint; cdecl;
begin
end;

{ Create and open a file

  If the file does not exist, first create it with the specified mode, and
  then open it.

  If this method is not implemented or under Linux kernel versions earlier
  than 2.6.15, the mknod() and open() methods will be called instead.

  Introduced in version 2.5
}
function qnx6_create(const aName: pchar; aMode: TMode; aFileInfo: PFuseFileInfo): cint; cdecl;
begin
  Result := FS.CreateFile(aName, aMode);
  if Result > 0 then Result := 0;
end;

{ Change the size of an open file

  This method is called instead of the truncate() method if the truncation
  was invoked from an ftruncate() system call.

  If this method is not implemented or under Linux kernel versions earlier
  than 2.6.15, the truncate() method will be called instead.

  Introduced in version 2.5
}
function qnx6_ftruncate(const aName: pchar; aSize: TOff; aFileInfo: PFuseFileInfo): cint; cdecl;
begin
end;

{ Get attributes from an open file

  This method is called instead of the getattr() method if the file
  information is available.

  Currently this is only called after the create() method if that is
  implemented (see above). Later it may be called for invocations of fstat()
  too.

  Introduced in version 2.5
}
function qnx6_fgetattr(const aName: pchar; aOutStat: PStat; PFileInfo: PFuseFileInfo): cint; cdecl;
begin
end;

{ Perform POSIX file locking operation

  The cmd argument will be either F_GETLK, F_SETLK or F_SETLKW.

  For the meaning of fields in 'struct flock' see the man page for fcntl(2).
  The l_whence field will always be set to SEEK_SET.

  For checking lock ownership, the 'fuse_file_info->owner'argument must be
  used.

  For F_GETLK operation, the library will first check currently held locks,
  and if a conflicting lock is found it will return information without
  calling this method. This ensures, that for local locks the l_pid field is
  correctly filled in. The results may not be accurate in case of race
  conditions and inthe presence of hard links, but it's unlikly that an
  application would rely on accurate GETLK results in these cases. If a
  conflicting lock is not found, this method will be called, and the
  filesystem may fill out l_pid by a meaningful value, or it may leave this
  field zero.

  or F_SETLK and F_SETLKW the l_pid field will be set to the pid of the
  process performing the locking operation.

  Note: if this method is not implemented, the kernel will still allow file
  locking to work locally. Hence it is only interesting for network
  filesystems and similar.

  Introduced in version 2.6
}
function qnx6_lock(const aName: pchar; aFileInfo: PFuseFileInfo; aCMD: cint; var aLock: FLock): cint; cdecl;
begin
end;

{ Change the access and modification times of a file with nanosecond
  resolution

  Introduced in version 2.6
}
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
{
  (getattr: @qnx6_getattr;
  readlink: nil;
  mknod: nil;
  mkdir: nil;
  unlink: nil;
  rmdir: nil;
  symlink: nil;
  rename: nil;
  link: nil;
  chmod: nil;
  chown: nil;
  truncate: nil;
  Open: @qnx6_open;
  Read: @qnx6_read;
  Write: nil;
  statfs: nil;
  flush: nil;
  Release: nil;
  fsync: nil;
  setxattr: nil;
  getxattr: nil;
  listxattr: nil;
  removexattr: nil;
  opendir: nil;
  readdir: @qnx6_readdir;
  releasedir: nil;
  fsyncdir: nil;
  init: nil;
  Destroy: nil;
  access: nil;
  Create: nil;
  lock: nil;
  utimens: nil;
  bmap: nil;
  );
}

procedure QNX6Mount(fileName, mountpoint: string; fg: boolean = False; dbg: boolean = False);
var
  fStream: TFileStream;
  _argc: integer;
  _argv: array of pchar;
  res, i: integer;
begin
  _argc := 4;
  {$IFDEF DEBUG}
  _argc := 5;
  {$ELSE}
  if fg then Inc(_argc);
  if dbg then Inc(_argc);
  i := 4;
  {$ENDIF}
  MP := ExpandFileName(mountpoint);

  SetLength(_argv, _argc);
  _argv[0] := PChar(fileName);
  _argv[1] := PChar(MP);
  _argv[2] := '-ofsname=qnx6';
  _argv[3] := '-s';
  {$IFDEF DEBUG}
  _argv[4] := '-d';
  _argv[4] := '-f';
  {$ELSE}
  if fg then
  begin
    _argv[i] := '-f';
    Inc(i);
  end;
  if dbg then
  begin
    _argv[i] := '-d';
    Inc(i);
  end;

  //_argv[4] := '-f';
  {$ENDIF}

  if FileExists(fileName) then
  begin
    fStream := TFileStream.Create(fileName, fmOpenReadWrite);
    try
      FS := TQNX6Fs.Create(fStream);
      try
        FS.Open;

        qnx6_oper := default(TFuseOperations);
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
          //fsync := @qnx6_fsync;
          //fsyncdir := @qnx6_fsyncdir;
          //flush := @qnx6_flush;
          Destroy := @qnx6_destroy;
        end;

        res := fuse_main(_argc, @_argv[0], @qnx6_oper, SizeOf(qnx6_oper), nil);

      finally
        FreeAndNil(FS);
      end;

    finally
      FreeAndNil(fStream);
    end;

  end;

end;


end.
