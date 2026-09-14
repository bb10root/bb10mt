unit uQNX;

{$mode ObjFPC}{$H+}

interface

uses
  CLI.Command,
  CLI.Console;

type
  {$IFDEF LINUX}
  TMountCommand = class(TBaseCommand)
  public
    function Execute: Integer; override;
  end;
  {$ENDIF}

  TQNX6Command = class(TBaseCommand)
  public
    function Execute: integer; override;
  end;

  TCompactCommand = class(TBaseCommand)
  public
    function Execute: integer; override;
  end;

  TFsckCommand = class(TBaseCommand)
  public
    function Execute: integer; override;
  end;

  TMkFSCommand = class(TBaseCommand)
  public
    function Execute: integer; override;
  end;

  TQNX6ScriptCommand = class(TBaseCommand)
  public
    function Execute: integer; override;
  end;

var
  {$IFDEF LINUX}
  Mnt: TMountCommand;
  {$ENDIF}
  QNX6cmd: TQNX6Command;
  Compact: TCompactCommand;
  mkFs: TMkFSCommand;
  fsck: TFsckCommand;
  ScriptCmd: TQNX6ScriptCommand;

implementation

uses
  SysUtils,
  Classes,
  {$IFDEF LINUX}
  fuseqnx6,
  {$ENDIF}
  FileUtil,
  qnx6.types, qnx6,
  QNX.Debloat, scripthandler;

{$IFDEF LINUX}
function TMountCommand.Execute: Integer;
var
  tmp, fsImage, mountPoint: string;
  debug, foreground: Boolean;
begin
  Result := 0;
  debug := False;
  foreground := False;

  if not GetParameterValue('--image', fsImage) then
  begin
    TConsole.WriteLn('--image is required!', ccRed);
    Exit(1);
  end;

  if not GetParameterValue('--mountpoint', mountPoint) then
  begin
    TConsole.WriteLn('--mountpoint is required!', ccRed);
    Exit(2);
  end;

  if GetParameterValue('--foreground', tmp) then
    foreground := StrToBool(tmp);
  if GetParameterValue('--debug', tmp) then
    debug := StrToBool(tmp);

  if debug then
    foreground := True;

  QNX6Mount(fsImage, mountPoint, foreground, debug);
end;
{$ENDIF}

function TQNX6ScriptCommand.Execute: integer;
var
  line, scriptName, imagePath, bList, scriptPath, debloatStr: string;
  script, blackList: TStringList;
  debloat: boolean = False;
begin
  Result := 0;
  blackList := nil;
  script := nil;

  if not GetParameterValue('--image', imagePath) then
  begin
    TConsole.WriteLn('❌ Missing required parameter: --image <path_to_image>');
    Exit(-1);
  end;

  if not FileExists(imagePath) then
  begin
    TConsole.WriteLn('❌ Image file does not exist: ' + imagePath);
    Exit(-1);
  end;

  if GetParameterValue('--debloat', debloatStr) then
    debloat := StrToBoolDef(debloatStr, False);

  scriptPath := '';
  scriptName := '';
  if GetParameterValue('--script', scriptPath) and (scriptPath <> '') then
  begin
    scriptName := ExpandFileName(scriptPath);
    if not FileExists(scriptName) then
    begin
      TConsole.WriteLn('❌ Script file does not exist: ' + scriptPath);
      Exit(-1);
    end;
  end;

  if debloat then
  begin
    if not GetParameterValue('--blacklist', bList) then
      bList := 'com.twitter com.evernote com.linkedin com.tcs.maps com.rim.bb.app.facebook ' +
        'com.rim.bb.app.retaildemoshim sys.socialconnect.linkedin sys.socialconnect.twitter ' +
        'sys.socialconnect.youtube sys.socialconnect.facebook sys.cfs.box sys.cfs.dropbox ' +
        'sys.uri.youtube sys.weather sys.appworld ' + 'sys.bbm';

    blackList := TStringList.Create;
    blackList.AddDelimitedText(bList, ' ', True);
  end;

  try
    runScript(imagePath, scriptName);
  finally
    if Assigned(blackList) then
      FreeAndNil(blackList);
  end;
end;

function TFsckCommand.Execute: integer;
var
  inputInline: string;
  fStream: TFileStream;
  QNXLocal: TQNX6Fs;
  Errors: TStringList;
  FixEnabled: boolean;
  i: integer;
begin
  Result := 1;
  Errors := nil;
  if GetParameterValue('--fix', inputInline) then
    FixEnabled := StrToBool(inputInline);

  if not GetParameterValue('--image', inputInline) then
  begin
    TConsole.WriteLn('❌ Missing required parameter: --image <path_to_image>');
    Exit;
  end;

  if not FileExists(inputInline) then
  begin
    TConsole.WriteLn('❌ Image file does not exist: ' + inputInline);
    Exit;
  end;

  fStream := TFileStream.Create(inputInline, fmOpenReadWrite);
  try
    QNXLocal := TQNX6Fs.Create(fStream);
    try
      QNXLocal.Open(True);
      Errors := TStringList.Create;
      QNXLocal.Fsck(Errors, FixEnabled);

      if Errors.Count > 0 then
      begin
        TConsole.WriteLn('');
        TConsole.WriteLn('===== Filesystem check results =====');
        for i := 0 to Errors.Count - 1 do
          WriteLn(Errors[i]);
        WriteLn('====================================');

        if FixEnabled then
          TConsole.WriteLn('✔ Fix applied where possible.')
        else
          TConsole.WriteLn('⚠ Use --fix to automatically correct fixable issues.');

        Result := 1;
      end
      else
      begin
        TConsole.WriteLn('✔ No errors found. Filesystem is clean.');
        Result := 0;
      end;
    finally
      FreeAndNil(Errors);
      FreeAndNil(QNXLocal);
    end;
  finally
    FreeAndNil(fStream);
  end;
end;

function TQNX6Command.Execute: integer;
begin
  Result := 0;
end;

function TCompactCommand.Execute: integer;
var
  imagePath: string;
  fs: TFileStream;
  qnx6: TQNX6Fs;
  blocksMoved: integer;
begin
  Result := 1;

  if not GetParameterValue('--image', imagePath) then
  begin
    TConsole.WriteLn('Error: missing required parameter "--image".');
    Exit;
  end;

  if not FileExists(imagePath) then
  begin
    TConsole.WriteLn('Error: file "' + imagePath + '" not found.');
    Exit;
  end;

  TConsole.WriteLn('Opening image: ' + imagePath);
  fs := TFileStream.Create(imagePath, fmOpenReadWrite);
  try
    qnx6 := TQNX6Fs.Create(fs);
    try
      try
        qnx6.Open(True);

        TConsole.WriteLn('Starting block compaction...');
        blocksMoved := qnx6.CompactBlocks;

        qnx6.Flush;
        TConsole.WriteLn('Filesystem changes flushed to disk.');

        Result := 0;
      except
        on E: Exception do
        begin
          TConsole.WriteLn('Fatal error during compaction: ' + E.Message);
          Result := 2;
        end;
      end;
    finally
      FreeAndNil(qnx6);
    end;
  finally
    FreeAndNil(fs);
  end;
end;

function TMkFSCommand.Execute: integer;
var
  sBlocks, sBlockSize, sInodes: string;
  tmps1: string;
  qnx6: TQNX6Fs;
  fs: TFileStream;
  Blocks, Inodes, BlockSize: integer;
begin
  Result := -1;

  if GetParameterValue('--image', tmps1) then
  begin
    fs := TFileStream.Create(tmps1, fmCreate);
    try
      qnx6 := TQNX6Fs.Create(fs);
      try
        GetParameterValue('--blocks', sBlocks);
        GetParameterValue('--inodes', sInodes);
        GetParameterValue('--block-size', sBlockSize);

        if not TryStrToInt(sBlocks, Blocks) then Blocks := 10240;
        if not TryStrToInt(sBlockSize, BlockSize) then BlockSize := 4096;
        if not TryStrToInt(sInodes, Inodes) then Inodes := 1024;

        qnx6.CreateImage(Blocks, BlockSize, Inodes);
        Result := 0;
      finally
        FreeAndNil(qnx6);
      end;
    finally
      FreeAndNil(fs);
    end;
  end;
end;

initialization

  QNX6cmd := TQNX6Command.Create('qnx6', 'QNX6 manipulations');

  ScriptCmd := TQNX6ScriptCommand.Create('script', 'execute script');
  ScriptCmd.AddPathParameter('-i', '--image', 'QNX6FS image file', True);
  ScriptCmd.AddPathParameter('-s', '--script', 'script file', True);
  ScriptCmd.AddFlag('-d', '--debloat', 'create debloat script');
  ScriptCmd.AddArrayParameter('-b', '--blacklist', 'apps to remove');

  Compact := TCompactCommand.Create('compact', 'compact QNX6 image');
  Compact.AddPathParameter('-i', '--image', 'QNX6FS image file', True);

  fsck := TFsckCommand.Create('fsck', 'Check QNX6 image');
  fsck.AddPathParameter('-i', '--image', 'QNX6FS image file', True);
  fsck.AddFlag('-f', '--fix', 'fix errors');

  mkFs := TMkFSCommand.Create('mkfs', 'Create QNX6 image');
  mkFs.AddPathParameter('-i', '--image', 'QNX6FS image file', True);
  mkFs.AddIntegerParameter('-b', '--blocks', 'Blocks count', False, '10240');
  mkFs.AddIntegerParameter('-n', '--inodes', 'Inodes count', False, '1024');
  mkFs.AddIntegerParameter('-s', '--block-size', 'Block Size (multiple of 512)', False, '4096');

  {$IFDEF LINUX}
  Mnt := TMountCommand.Create('mount', 'mount QNX image');
  Mnt.AddPathParameter('-m', '--mountpoint', 'mounting point', True);
  Mnt.AddPathParameter('-i', '--image', 'QNX6FS image file', True);
  Mnt.AddFlag('-f', '--foreground', 'run foreground');
  Mnt.AddFlag('-d', '--debug', 'output FUSE debug info (!)Slooo....');
  QNX6cmd.AddSubCommand(Mnt);
  {$ENDIF}
  QNX6cmd.AddSubCommand(Compact);
  QNX6cmd.AddSubCommand(mkFs);
  QNX6cmd.AddSubCommand(fsck);
  QNX6cmd.AddSubCommand(ScriptCmd);

end.
