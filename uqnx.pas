unit uQNX;

{$mode ObjFPC}{$H+}

interface

uses
  CLI.Interfaces,    // Core interfaces
  CLI.Command,       // Base command implementation
  CLI.Parameter,     // Parameter handling
  CLI.Progress,      // Optional: Progress indicators
  CLI.Console;       // Optional: Colored console output


type
  {$IFDEF LINUX}
  TMountCommand = class(TBaseCommand)
  public
    function Execute: integer; override;
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

var
  {$IFDEF LINUX}
  Mnt: TMountCommand;
  {$ENDIF}
  QNX6cmd: TQNX6Command;
  Compact: TCompactCommand;
  mkFs: TMkFSCommand;
  fsck: TFsckCommand;


implementation

uses
  SysUtils,
  Classes,
  {$IFDEF LINUX}
  fuseqnx6,
  {$ENDIF}
  qnx6;


{$IFDEF LINUX}
function TMountCommand.Execute: Integer;
var
  tmp, fsImage, mountPoint: string;
  debug, foreground: Boolean;
begin
  Result := 0;
  debug := false;
  foreground := false;

  // Обов'язкові параметри
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

  // Опції
  //debug := GetParameterValue('--debug', tmp);
  foreground := GetParameterValue('--foreground', tmp);

  // Якщо включено debug — автоматично переходимо у foreground
  if debug then
    foreground := True;

  // Виконання монтування
  QNX6Mount(fsImage, mountPoint, foreground, debug);
end;
{$ENDIF}


function TFsckCommand.Execute: integer;
var
  inputInline: string;
  fStream: TFileStream;
  QNX: TQNX6Fs;
  Errors: TStringList;
  FixEnabled: boolean;
  i: integer;
begin
  Result := 1; // припускаємо помилку
  Errors := nil;
  FixEnabled := GetParameterValue('--fix', inputInline);

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
    QNX := TQNX6Fs.Create(fStream);
    try
      QNX.Open(True);
      Errors := TStringList.Create;
      QNX.Fsck(Errors, FixEnabled);

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
      Errors.Free;
      QNX.Free;
    end;

  finally
    fStream.Free;
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
  blocksMoved, inodesUpdated: integer;
begin
  Result := 1; // 1 — помилка за замовчуванням

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

        //        TConsole.WriteLn('Starting inode compaction...');
        //        inodesUpdated := qnx6.CompactInodes;

        qnx6.Flush;
        TConsole.WriteLn('Filesystem changes flushed to disk.');

        Result := 0; // успіх
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
        if not TryStrToInt(sBlocks, Blocks) then
          Blocks := 10240;
        if not TryStrToInt(sBlockSize, BlockSize) then
          BlockSize := 4096;
        if not TryStrToInt(sInodes, Inodes) then
          Inodes := 1024;

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
  Mnt.AddPathParameter('-i', '--image', 'QNX6FS image file', True);
  Mnt.AddPathParameter('-m', '--mountpoint', 'mounting point', True);
  Mnt.AddFlag('-f', '--foreground', 'run foreground');
  Mnt.AddFlag('-d', '--debug', 'output FUSE debug info (!)Slooo....');
  QNX6cmd.AddSubCommand(Mnt);
  {$ENDIF}
  QNX6cmd.AddSubCommand(Compact);
  QNX6cmd.AddSubCommand(mkFs);
  QNX6cmd.AddSubCommand(fsck);

end.
