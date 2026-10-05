unit QNX.Commands.Script;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, qnx6, qnx6.types, QNX.Utils, uScript;

type
  TMkDirCommand = class(TBasicCommand)
  private
    FFS: TQNX6Fs;
  public
    constructor Create(const AName, AHelp, AUsage: string; AFS: TQNX6Fs);
    function Execute(const Args: array of string): integer; override;
  end;

  TPushCommand = class(TBasicCommand)
  private
    FFS: TQNX6Fs;
  public
    constructor Create(const AName, AHelp, AUsage: string; AFS: TQNX6Fs);
    function Execute(const Args: array of string): integer; override;
  end;

  TTouchCommand = class(TBasicCommand)
  private
    FFS: TQNX6Fs;
  public
    constructor Create(const AName, AHelp, AUsage: string; AFS: TQNX6Fs);
    function Execute(const Args: array of string): integer; override;
  end;

  TChmodCommand = class(TBasicCommand)
  private
    FFS: TQNX6Fs;
  public
    constructor Create(const AName, AHelp, AUsage: string; AFS: TQNX6Fs);
    function Execute(const Args: array of string): integer; override;
  end;

  TChownCommand = class(TBasicCommand)
  private
    FFS: TQNX6Fs;
    procedure ParseOwnerGroup(const Arg: string; var Uid, Gid: integer; var Valid: boolean);
  public
    constructor Create(const AName, AHelp, AUsage: string; AFS: TQNX6Fs);
    function Execute(const Args: array of string): integer; override;
  end;

  TReplaceCommand = class(TBasicCommand)
  private
    FFS: TQNX6Fs;
  public
    constructor Create(const AName, AHelp, AUsage: string; AFS: TQNX6Fs);
    function Execute(const Args: array of string): integer; override;
  end;

  TRemoveAppCommand = class(TBasicCommand)
  private
    FFS: TQNX6Fs;
  public
    constructor Create(const AName, AHelp, AUsage: string; AFS: TQNX6Fs);
    function Execute(const Args: array of string): integer; override;
  end;

  TRmCommand = class(TBasicCommand)
  private
    FFS: TQNX6Fs;
  public
    constructor Create(const AName, AHelp, AUsage: string; AFS: TQNX6Fs);
    function Execute(const Args: array of string): integer; override;
  end;

  TAddStringCommand = class(TBasicCommand)
  private
    FFS: TQNX6Fs;
  public
    constructor Create(const AName, AHelp, AUsage: string; AFS: TQNX6Fs);
    function Execute(const Args: array of string): integer; override;
  end;

function ApplyChmod(FS: TQNX6Fs; const Path: string; Mode: integer; Recursive: boolean): integer;
function ApplyChown(FS: TQNX6Fs; const Path: string; Uid, Gid: integer; Recursive: boolean): integer;

implementation

uses
  CLI.Console;

const
  PATH_REGISTERED_APPS = '/var/pps/system/installer/registeredapps/applications';
  PATH_APP_DETAILS = '/var/pps/system/installer/appdetails';
  PATH_APPS = '/apps';

type
  TRegList = record
    Name: string;
    Data: TStringList;
    Changed: boolean;
  end;

  { Private Helper Functions }

function ApplyChmodByInode(FS: TQNX6Fs; Idx: DWord; const Path: string; Mode: integer;
  Recursive: boolean): integer; forward;

function ApplyChmod(FS: TQNX6Fs; const Path: string; Mode: integer; Recursive: boolean): integer;
var
  Idx: DWord;
begin
  Result := -1;
  if FS = nil then Exit;

  Idx := FS.GetInodeByPath(PChar(Path));
  if Idx = 0 then
  begin
    TConsole.WriteLn(Format('chmod: [ERROR] Path "%s" not found', [Path]));
    Exit;
  end;
  TConsole.WriteLn(Format('chmod: [INFO] Mode set to %s for "%s"', [OctStr(Mode and $0FFF, 4), Path]));

  Result := ApplyChmodByInode(FS, Idx, Path, Mode, Recursive);
end;

function ApplyChmodByInode(FS: TQNX6Fs; Idx: DWord; const Path: string; Mode: integer;
  Recursive: boolean): integer;
var
  I, Count: integer;
  Inode: TQNX6_DInode;
  RDI: TQNX6_ARawDirEntry;
  Name, ChildPath, BasePath: string;
  HadError: boolean;
begin
  HadError := False;
  Inode := FS.GetInode(Idx);

  if Recursive and FpS_ISDIR(Inode.mode) then
  begin
    Count := FS.ReadDirectory(Idx, RDI);
    if Count < 0 then
    begin
      TConsole.WriteLn(Format('chmod: [ERROR] Cannot read directory "%s"', [Path]));
      HadError := True;
    end
    else if Count > 0 then
    begin
      BasePath := EnsurePOSIXTrailingSlash(Path);
      for I := 0 to Pred(Count) do
      begin
        Name := FS.RawDirEntryGetName(RDI[I]);
        if (Name <> '.') and (Name <> '..') then
        begin
          ChildPath := BasePath + Name;
          if ApplyChmodByInode(FS, RDI[I].inode, ChildPath, Mode, True) <> 0 then
            HadError := True;
        end;
      end;
    end;
    SetLength(RDI, 0);
  end;

  Inode.mode := (Inode.mode and not $0FFF) or (Mode and $0FFF);
  FS.SetInode(Idx, Inode);

  if HadError then
    Result := -1
  else
    Result := 0;
end;

function ApplyChown(FS: TQNX6Fs; const Path: string; Uid, Gid: integer; Recursive: boolean): integer;
var
  Idx: DWord;
  I, Count: integer;
  Inode: TQNX6_DInode;
  RDI: TQNX6_ARawDirEntry;
  Name, ChildPath, BasePath: string;
begin
  Result := -1;
  if FS = nil then Exit;

  Idx := FS.GetInodeByPath(PChar(Path));
  if Idx > 0 then
  begin
    Inode := FS.GetInode(Idx);

    if Recursive and FpS_ISDIR(Inode.mode) then
    begin
      Count := FS.ReadDirectory(Idx, RDI);
      if Count > 0 then
      begin
        BasePath := EnsurePOSIXTrailingSlash(Path);
        for I := 0 to Pred(Count) do
        begin
          Name := FS.RawDirEntryGetName(RDI[I]);
          if (Name <> '.') and (Name <> '..') then
          begin
            ChildPath := BasePath + Name;
            ApplyChown(FS, ChildPath, Uid, Gid, True);
          end;
        end;
      end;
      SetLength(RDI, 0);
    end;

    if Uid <> -1 then Inode.uid := cardinal(Uid);
    if Gid <> -1 then Inode.gid := cardinal(Gid);

    FS.SetInode(Idx, Inode);

    if not Recursive then
      TConsole.WriteLn(Format('chown: [INFO] Owner/group set to %d:%d for "%s"', [Uid, Gid, Path]));

    Result := 0;
  end
  else
    TConsole.WriteLn(Format('chown: [ERROR] Path "%s" not found', [Path]));
end;

function ReplaceInStream(Stream: TMemoryStream; const OldStr, NewStr: rawbytestring): boolean;
var
  DataStr, ModifiedStr: rawbytestring;
begin
  Result := False;
  if (Stream = nil) or (Stream.Size = 0) or (OldStr = '') then Exit;

  Stream.Position := 0;
  SetLength(DataStr, Stream.Size);
  Stream.Read(DataStr[1], Stream.Size);

  ModifiedStr := StringReplace(DataStr, OldStr, NewStr, [rfReplaceAll]);

  if DataStr <> ModifiedStr then
  begin
    Stream.Clear;
    if Length(ModifiedStr) > 0 then
      Stream.Write(ModifiedStr[1], Length(ModifiedStr));
    Result := True;
  end;

  Stream.Position := 0;
end;

function LoadPPSList(FS: TQNX6Fs; const FilePath: string; TargetList: TStringList;
  Stream: TMemoryStream): boolean;
begin
  Result := False;
  Stream.Clear;
  if qnx6_readFile(FS, FilePath, Stream) = 0 then
  begin
    Stream.Position := 0;
    TargetList.LoadFromStream(Stream);
    Result := True;
  end;
end;

function SavePPSList(FS: TQNX6Fs; const FilePath: string; SourceList: TStringList;
  Stream: TMemoryStream): boolean;
begin
  Stream.Clear;
  SourceList.SaveToStream(Stream);
  Stream.Position := 0;
  Result := qnx6_writeFile(FS, FilePath, Stream) = 0;
end;

{ TMkDirCommand }

constructor TMkDirCommand.Create(const AName, AHelp, AUsage: string; AFS: TQNX6Fs);
begin
  inherited Create(AName, AHelp, AUsage);
  FFS := AFS;
end;

function TMkDirCommand.Execute(const Args: array of string): integer;
var
  TargetDir: string;
  IsRecursive: boolean;
begin
  Result := -1;
  IsRecursive := False;
  TargetDir := '';

  if (Length(Args) = 2) and (Args[0] = '-p') then
  begin
    IsRecursive := True;
    TargetDir := Args[1];
  end
  else if Length(Args) = 1 then
  begin
    TargetDir := Args[0];
  end
  else
  begin
    TConsole.WriteLn('[ERROR] Invalid argument count.');
    TConsole.WriteLn('[USAGE] mkdir [-p] <directory_path>');
    Exit(1);
  end;

  TargetDir := Path2QNX(TargetDir);
  if (TargetDir = '') or (TargetDir[1] <> '/') then
    TargetDir := '/' + TargetDir;

  if qnx6_MkDir(FFS, TargetDir, IsRecursive) then
  begin
    TConsole.WriteLn(Format('[INFO] Successfully created directory "%s"', [TargetDir]));
    Result := 0;
  end
  else
    TConsole.WriteLn(Format('[ERROR] Failed to create directory "%s"', [TargetDir]));
end;

{ TPushCommand }

constructor TPushCommand.Create(const AName, AHelp, AUsage: string; AFS: TQNX6Fs);
begin
  inherited Create(AName, AHelp, AUsage);
  FFS := AFS;
end;

function TPushCommand.Execute(const Args: array of string): integer;
var
  SrcPath, DstPath: string;
  IsDir: boolean;
  PushedCount: integer;
begin
  Result := -1;

  if Length(Args) <> 2 then
  begin
    TConsole.WriteLn('[ERROR] Invalid argument count.');
    TConsole.WriteLn('[USAGE] push <local_src_path> <qnx_dst_path>');
    Exit(1);
  end;

  SrcPath := ExpandFileName(Args[0]);
  IsDir := DirectoryExists(SrcPath);

  if not IsDir and not FileExists(SrcPath) then
  begin
    TConsole.WriteLn(Format('[ERROR] Source path "%s" does not exist', [SrcPath]));
    Exit(2);
  end;

  DstPath := Args[1];
  if (DstPath = '') or (DstPath[1] <> '/') then
    DstPath := '/' + DstPath;

  // Обробка одиничного файлу
  if not IsDir then
  begin
    if DstPath.EndsWith('/') then
      DstPath := DstPath + ExtractFileName(SrcPath);

    if qnx6_PushFile(FFS, SrcPath, DstPath) = 0 then
    begin
      TConsole.WriteLn(Format('[INFO] Pushed file "%s" -> "%s"', [SrcPath, DstPath]));
      Exit(0);
    end
    else
    begin
      TConsole.WriteLn(Format('[ERROR] Failed to push file "%s"', [SrcPath]));
      Exit(3);
    end;
  end;

  // Обробка каталогу та всього піддерева
  if DstPath.EndsWith('/') then
    DstPath := DstPath + ExtractFileName(ExcludeTrailingPathDelimiter(SrcPath));

  TConsole.WriteLn(Format('[INFO] Pushing directory structure from "%s" to "%s"...', [SrcPath, DstPath]));

  PushedCount := qnx6_PushDir(FFS, SrcPath, DstPath);
  if PushedCount >= 0 then
  begin
    TConsole.WriteLn(Format('[INFO] Push completed successfully. Total files pushed: %d', [PushedCount]));
    Result := 0;
  end
  else
  begin
    TConsole.WriteLn(Format('[ERROR] Failed to push directory "%s"', [SrcPath]));
    Result := 4;
  end;
end;

{ TTouchCommand }

constructor TTouchCommand.Create(const AName, AHelp, AUsage: string; AFS: TQNX6Fs);
begin
  inherited Create(AName, AHelp, AUsage);
  FFS := AFS;
end;

function TTouchCommand.Execute(const Args: array of string): integer;
var
  Target: string;
begin
  Result := -1;

  if Length(Args) = 1 then
    Target := Args[0]
  else
  begin
    TConsole.WriteLn('[ERROR] Invalid argument count.');
    TConsole.WriteLn('[USAGE] touch <file_name>');
    Exit(1);
  end;

  Target := Path2QNX(Target);
  if (Target = '') or (Target[1] <> '/') then
    Target := '/' + Target;

  if FFS.CreateFile(PChar(Target), &666) = 0 then
  begin
    TConsole.WriteLn(Format('[INFO] Successfully touched file "%s"', [Target]));
    Result := 0;
  end
  else
    TConsole.WriteLn(Format('[ERROR] Failed to create file "%s"', [Target]));
end;

{ TChmodCommand }

constructor TChmodCommand.Create(const AName, AHelp, AUsage: string; AFS: TQNX6Fs);
begin
  inherited Create(AName, AHelp, AUsage);
  FFS := AFS;
end;

function TChmodCommand.Execute(const Args: array of string): integer;
var
  Mode: integer;
  TargetFile, ModeStr: string;
  IsRecursive: boolean;
begin
  IsRecursive := False;
  ModeStr := '';
  TargetFile := '';

  if (Length(Args) = 3) and (Args[0] = '-R') then
  begin
    IsRecursive := True;
    ModeStr := Args[1];
    TargetFile := Args[2];
  end
  else if Length(Args) = 2 then
  begin
    ModeStr := Args[0];
    TargetFile := Args[1];
  end
  else
  begin
    TConsole.WriteLn('[ERROR] Invalid argument count.');
    TConsole.WriteLn('[USAGE] chmod [-R] <mode> <filename/directory>');
    Exit(1);
  end;

  try
    if (Length(ModeStr) > 0) and (ModeStr[1] <> '&') then
      Mode := StrToInt('&' + ModeStr)
    else
      Mode := StrToInt(ModeStr);
  except
    on E: EConvertError do
    begin
      TConsole.WriteLn(Format('[ERROR] Invalid mode format "%s". Use octal (e.g., 755).', [ModeStr]));
      Exit(2);
    end;
  end;

  Result := ApplyChmod(FFS, TargetFile, Mode, IsRecursive);
  if Result = 0 then
  begin
    if IsRecursive then
      TConsole.WriteLn(Format('chmod: [INFO] Recursively applied mode %s to "%s"',
        [OctStr(Mode and $0FFF, 4), TargetFile]))
    else
      TConsole.WriteLn('chmod: [INFO] Operation completed successfully');
  end
  else
    TConsole.WriteLn('chmod: [ERROR] Operation failed');
end;

{ TChownCommand }

constructor TChownCommand.Create(const AName, AHelp, AUsage: string; AFS: TQNX6Fs);
begin
  inherited Create(AName, AHelp, AUsage);
  FFS := AFS;
end;

procedure TChownCommand.ParseOwnerGroup(const Arg: string; var Uid, Gid: integer; var Valid: boolean);
var
  ColonPos: integer;
  UidStr, GidStr: string;
begin
  Valid := True;
  ColonPos := Pos(':', Arg);
  if ColonPos = 0 then ColonPos := Pos('.', Arg);

  try
    if ColonPos > 0 then
    begin
      UidStr := Copy(Arg, 1, ColonPos - 1);
      GidStr := Copy(Arg, ColonPos + 1, Length(Arg) - ColonPos);

      if UidStr = '' then Uid := -1
      else
        Uid := StrToInt(UidStr);

      if GidStr = '' then Gid := -1
      else
        Gid := StrToInt(GidStr);
    end
    else
    begin
      Uid := StrToInt(Arg);
      Gid := -1;
    end;
  except
    on E: EConvertError do Valid := False;
  end;
end;

function TChownCommand.Execute(const Args: array of string): integer;
var
  Uid, Gid: integer;
  TargetFile, OwnerGroupStr: string;
  IsRecursive, IsValidFormat: boolean;
begin
  IsRecursive := False;
  OwnerGroupStr := '';
  TargetFile := '';

  if (Length(Args) = 3) and (Args[0] = '-R') then
  begin
    IsRecursive := True;
    OwnerGroupStr := Args[1];
    TargetFile := Args[2];
  end
  else if Length(Args) = 2 then
  begin
    OwnerGroupStr := Args[0];
    TargetFile := Args[1];
  end
  else
  begin
    TConsole.WriteLn('[ERROR] Invalid argument count.');
    TConsole.WriteLn('[USAGE] chown [-R] [owner][:group] <filename/directory>');
    Exit(1);
  end;

  ParseOwnerGroup(OwnerGroupStr, Uid, Gid, IsValidFormat);
  if not IsValidFormat then
  begin
    TConsole.WriteLn(Format('[ERROR] Invalid owner/group format "%s"', [OwnerGroupStr]));
    Exit(2);
  end;

  Result := ApplyChown(FFS, TargetFile, Uid, Gid, IsRecursive);
  if Result = 0 then
  begin
    if IsRecursive then
      TConsole.WriteLn(Format('chown: [INFO] Recursively applied owner/group %d:%d to "%s"',
        [Uid, Gid, TargetFile]))
    else
      TConsole.WriteLn('chown: [INFO] Operation completed successfully');
  end
  else
    TConsole.WriteLn('chown: [ERROR] Operation failed');
end;

{ TReplaceCommand }

constructor TReplaceCommand.Create(const AName, AHelp, AUsage: string; AFS: TQNX6Fs);
begin
  inherited Create(AName, AHelp, AUsage);
  FFS := AFS;
end;

function TReplaceCommand.Execute(const Args: array of string): integer;
var
  TargetFile, OldVal, NewVal: string;
  MS: TMemoryStream;
begin
  if Length(Args) <> 3 then
  begin
    TConsole.WriteLn('[ERROR] Invalid argument count.');
    TConsole.WriteLn('[USAGE] replace <file> <old_value> <new_value>');
    Exit(1);
  end;

  TargetFile := Args[0];
  OldVal := Args[1];
  NewVal := Args[2];

  TConsole.WriteLn(Format('[INFO] Replacing "%s" with "%s" in file "%s"...', [OldVal, NewVal, TargetFile]));

  MS := TMemoryStream.Create;
  try
    if qnx6_readFile(FFS, TargetFile, MS) <> 0 then
    begin
      TConsole.WriteLn(Format('[ERROR] File "%s" not found or unreadable', [TargetFile]));
      Exit(1);
    end;

    if ReplaceInStream(MS, OldVal, NewVal) then
    begin
      if qnx6_writeFile(FFS, TargetFile, MS) <> 0 then
      begin
        TConsole.WriteLn(Format('[ERROR] Write error for file "%s"', [TargetFile]));
        Exit(1);
      end;
      TConsole.WriteLn(Format('[INFO] Successfully updated file "%s"', [TargetFile]));
    end
    else
    begin
      TConsole.WriteLn(Format('[NOTICE] Target string "%s" not found in "%s". File unchanged.',
        [OldVal, TargetFile]));
    end;

    Result := 0;
  finally
    FreeAndNil(MS);
  end;
end;

{ TRemoveAppCommand }

constructor TRemoveAppCommand.Create(const AName, AHelp, AUsage: string; AFS: TQNX6Fs);
begin
  inherited Create(AName, AHelp, AUsage);
  FFS := AFS;
end;

function TRemoveAppCommand.Execute(const Args: array of string): integer;
var
  I, J, K: integer;
  BlackList, Registered: TStringList;
  Details: array of TRegList;
  BlacklistedApp, AppPath, CleanArg: string;
  AppDetailsEntries, AppsEntries: TDirEntryInfoArray;
  MS: TMemoryStream;
  FoundInApps, RegChanged: boolean;
begin
  Result := -1;

  if FFS = nil then
  begin
    TConsole.WriteLn('[ERROR] File system context is not initialized.');
    Exit;
  end;

  BlackList := TStringList.Create;
  Registered := TStringList.Create;
  MS := TMemoryStream.Create;
  try
    for I := 0 to Length(Args) - 1 do
    begin
      CleanArg := Trim(Args[I]);
      if CleanArg <> '' then
        BlackList.Add(CleanArg);
    end;

    if BlackList.Count = 0 then
    begin
      TConsole.WriteLn('[ERROR] Invalid argument count.');
      TConsole.WriteLn('[USAGE] removeapp <app_name_1> [<app_name_2> ...]');
      Exit(1);
    end;

    LoadPPSList(FFS, PATH_REGISTERED_APPS, Registered, MS);

    if qnx6_readDir(FFS, PATH_APP_DETAILS, AppDetailsEntries) <> 0 then
    begin
      TConsole.WriteLn(Format('[ERROR] Unable to read directory "%s"', [PATH_APP_DETAILS]));
      Exit;
    end;

    SetLength(Details, Length(AppDetailsEntries));
    for I := 0 to High(AppDetailsEntries) do
    begin
      Details[I].Name := AppDetailsEntries[I].Name;
      Details[I].Data := TStringList.Create;
      Details[I].Changed := False;

      LoadPPSList(FFS, PATH_APP_DETAILS + '/' + Details[I].Name, Details[I].Data, MS);
    end;

    if qnx6_readDir(FFS, PATH_APPS, AppsEntries) = 0 then
    begin
      TConsole.WriteLn(Format('[INFO] Starting application removal process for %d target(s)...',
        [BlackList.Count]));
      RegChanged := False;

      for BlacklistedApp in BlackList do
      begin
        for J := Registered.Count - 1 downto 0 do
        begin
          if Pos(BlacklistedApp, Registered[J]) > 0 then
          begin
            Registered.Delete(J);
            RegChanged := True;
          end;
        end;

        for J := 0 to High(Details) do
        begin
          for K := Details[J].Data.Count - 1 downto 0 do
          begin
            if Pos(BlacklistedApp, Details[J].Data[K]) > 0 then
            begin
              Details[J].Data.Delete(K);
              Details[J].Changed := True;
            end;
          end;
        end;

        FoundInApps := False;
        for J := 0 to High(AppsEntries) do
        begin
          if Pos(BlacklistedApp, AppsEntries[J].Name) > 0 then
          begin
            FoundInApps := True;
            AppPath := PATH_APPS + '/' + AppsEntries[J].Name;
            if qnx6_RmDir(FFS, AppPath, True) then
              TConsole.WriteLn(Format('[INFO] Removed "%s" from "%s"', [AppsEntries[J].Name, PATH_APPS]))
            else
              TConsole.WriteLn(Format('[ERROR] Failed to remove "%s" from "%s"',
                [AppsEntries[J].Name, PATH_APPS]));
          end;
        end;

        if not FoundInApps then
          TConsole.WriteLn(Format('[NOTICE] Target "%s" not found in "%s"', [BlacklistedApp, PATH_APPS]));
      end;

      if RegChanged then
        SavePPSList(FFS, PATH_REGISTERED_APPS, Registered, MS);

      for J := 0 to High(Details) do
      begin
        if Details[J].Changed then
        begin
          AppPath := PATH_APP_DETAILS + '/' + Details[J].Name;

          if Details[J].Data.Count = 0 then
            qnx6_Rm(FFS, AppPath)
          else
            SavePPSList(FFS, AppPath, Details[J].Data, MS);
        end;
      end;

      TConsole.WriteLn('[INFO] Application removal process finished successfully.');
      Result := 0;
    end;

  finally
    for I := 0 to High(Details) do
      if Details[I].Data <> nil then
        FreeAndNil(Details[I].Data);

    FreeAndNil(MS);
    FreeAndNil(Registered);
    FreeAndNil(BlackList);
  end;
end;

{ TRmCommand }

constructor TRmCommand.Create(const AName, AHelp, AUsage: string; AFS: TQNX6Fs);
begin
  inherited Create(AName, AHelp, AUsage);
  FFS := AFS;
end;

function TRmCommand.Execute(const Args: array of string): integer;
var
  I: integer;
  ArgStr: string;
  Recursive: boolean;
  Targets: TStringList;
  SuccessCount, FailCount: integer;
begin
  Result := 0;
  Recursive := False;

  if FFS = nil then
  begin
    TConsole.WriteLn('rm: [ERROR] File system context is not initialized.');
    Exit(1);
  end;

  Targets := TStringList.Create;
  try
    for I := 0 to Length(Args) - 1 do
    begin
      ArgStr := Trim(Args[I]);
      if ArgStr = '' then Continue;

      if (ArgStr = '-r') or (ArgStr = '-R') or (ArgStr = '-rf') or (ArgStr = '-fr') then
        Recursive := True
      else if (Length(ArgStr) > 0) and (ArgStr[1] <> '-') then
        Targets.Add(ArgStr);
    end;

    if Targets.Count = 0 then
    begin
      TConsole.WriteLn('rm: [ERROR] Missing operand');
      TConsole.WriteLn('[USAGE] rm [-r|-R] <file/directory>');
      Exit(1);
    end;

    SuccessCount := 0;
    FailCount := 0;

    for I := 0 to Targets.Count - 1 do
    begin
      ArgStr := Targets[I];

      if Recursive then
      begin
        if qnx6_RmDir(FFS, ArgStr, True) then
        begin
          TConsole.WriteLn(Format('rm: [INFO] Removed "%s"', [ArgStr]));
          Inc(SuccessCount);
        end
        else
        begin
          TConsole.WriteLn(Format('rm: [ERROR] Cannot remove "%s": Directory or file removal failed',
            [ArgStr]));
          Inc(FailCount);
        end;
      end
      else
      begin
        if qnx6_Rm(FFS, ArgStr) then
        begin
          TConsole.WriteLn(Format('rm: [INFO] Removed file "%s"', [ArgStr]));
          Inc(SuccessCount);
        end
        else
        begin
          if qnx6_RmDir(FFS, ArgStr, False) then
          begin
            TConsole.WriteLn(Format('rm: [INFO] Removed empty directory "%s"', [ArgStr]));
            Inc(SuccessCount);
          end
          else
          begin
            TConsole.WriteLn(Format('rm: [ERROR] Cannot remove "%s": No such file or directory not empty',
              [ArgStr]));
            Inc(FailCount);
          end;
        end;
      end;
    end;

    if FailCount > 0 then
      Result := 1;
  finally
    FreeAndNil(Targets);
  end;
end;

{ TAddStringCommand }

constructor TAddStringCommand.Create(const AName, AHelp, AUsage: string; AFS: TQNX6Fs);
begin
  inherited Create(AName, AHelp, AUsage);
  FFS := AFS;
end;

function TAddStringCommand.Execute(const Args: array of string): integer;
var
  MS: TMemoryStream;
  SL: TStringList;
  FilePath, NewString: string;
begin
  Result := -1;

  if FFS = nil then
  begin
    TConsole.WriteLn('[ERROR] File system context is not initialized.');
    Exit;
  end;

  if Length(Args) <> 2 then
  begin
    TConsole.WriteLn('[ERROR] Invalid argument count.');
    TConsole.WriteLn('[USAGE] addstring <file> <string>');
    Exit(1);
  end;

  FilePath := Path2QNX(Trim(Args[0]));
  NewString := Args[1];

  MS := TMemoryStream.Create;
  SL := TStringList.Create;
  try
    if qnx6_readFile(FFS, FilePath, MS) = 0 then
    begin
      MS.Position := 0;
      SL.LoadFromStream(MS);
    end;

    if SL.IndexOf(NewString) <> -1 then
    begin
      TConsole.WriteLn(Format('[NOTICE] String "%s" already exists in "%s". Skipping.',
        [NewString, FilePath]));
      Exit(0);
    end;

    SL.Add(NewString);

    MS.Clear;
    SL.SaveToStream(MS);
    MS.Position := 0;

    if qnx6_writeFile(FFS, FilePath, MS) = 0 then
    begin
      TConsole.WriteLn(Format('[INFO] Added "%s" to "%s"', [NewString, FilePath]));
      Result := 0;
    end
    else
      TConsole.WriteLn(Format('[ERROR] Failed to write to file "%s"', [FilePath]));

  finally
    FreeAndNil(SL);
    FreeAndNil(MS);
  end;
end;

end.
