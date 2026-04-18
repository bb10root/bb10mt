unit uRCFS;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils,
  CLI.Interfaces,    // Core interfaces
  CLI.Command,       // Base command implementation
  CLI.Progress,      // Optional: Progress indicators
  CLI.Console;       // Optional: Colored console output

type
  TRCFSCommand = class(TBaseCommand)
  public
    function Execute: integer; override;
  end;

  TRCFSExtract = class(TBaseCommand)
  public
    function Execute: integer; override;
  end;

  TRCFSVMDK = class(TBaseCommand)
  public
    function Execute: integer; override;
  end;

  TRCFSModify = class(TBaseCommand)
  public
    function Execute: integer; override;
  end;

var
  RCFSCommand: TRCFSCommand;
  RCFSVMDK: TRCFSVMDK;
  RCFSExtract: TRCFSExtract;
  RCFSModify: TRCFSModify;

implementation

uses rcfs, uVMDK, uScript;

var
  fRCFS: TRCFS = nil;

type
  TPushCommand = class(TBasicCommand)
  public
    function Execute(const Args: array of string): integer; override;
  end;

  TChmodCommand = class(TBasicCommand)
  public
    function Execute(const Args: array of string): integer; override;
  end;

  TCorruptCommand = class(TBasicCommand)
  public
    function Execute(const Args: array of string): integer; override;
  end;


function TPushCommand.Execute(const Args: array of string): integer;
var
  src, dst: string;
begin
  if Length(Args) <> 2 then
  begin
    Writeln(Args[0], ': Wrong arguments count');
    exit(1);
  end;
  src := ExpandFileName(Args[0]);
  if not FileExists(src) then
  begin
    Writeln('Error: ', Args[0], ' not exists');
    exit(2);
  end;
  if Args[1][1] = '/' then
    dst := Args[1]
  else
    dst := '/' + Args[1];

  Result := fRCFS.replaceFile(dst, src);

end;

function TChmodCommand.Execute(const Args: array of string): integer;
var
  mode: integer;
begin
  if Length(Args) <> 2 then
  begin
    Writeln('Error: Wrong arguments count');
    exit(1);
  end;

  try
    mode := StrToInt('&' + Args[0]);
  except
    On E: EConvertError do
    begin
      WriteLn('Error: wrong mode "', Args[0], '"');
      exit(2);
    end;
  end;

  Result := fRCFS.chmod(Args[1], mode);

end;

function TCorruptCommand.Execute(const Args: array of string): integer;
var
  mode: integer;
begin
  if Length(Args) <> 2 then
  begin
    Writeln('Error: Wrong arguments count');
    exit(1);
  end;

  Result := fRCFS.corruptFile(Args[1]);

end;

function TRCFSCommand.Execute: integer;
begin

end;

function TRCFSModify.Execute: integer;
var
  fStream: TStream;
  line, image, _image, scriptName, _scriptName, targetFile: string;
  i, k: integer;
  script: TStringList;

  CmdList: ICommandList;
begin
  Result := 1;

  GetParameterValue('--image', _image);
  image := ExpandFileName(_image);
  GetParameterValue('--script', _scriptName);
  scriptName := ExpandFileName(_scriptName);
  if (_scriptName <> '') and not FileExists(scriptName) then
  begin
    WriteLn('Script file: "', _scriptName, '" not exists');
    Exit(-1);
  end;

  GetParameterValue('--corrupt', targetFile);
  if ((targetFile = '') and (_scriptName = '')) then
  begin
    WriteLn('Nothing to do...');
    Exit(-2);
  end;


  fStream := nil;
  script := nil;
  try
    fStream := TFileStream.Create(image, fmOpenReadWrite or fmShareDenyWrite);

    fRCFS := TRCFS.Create(fStream);
    try
      if _scriptName <> '' then
      begin
        script := TStringList.Create;
        try
          script.LoadFromFile(scriptName);
          CmdList := TCommandList.Create;
          CmdList.RegisterCommand(
            TPushCommand.Create('push', 'push file to image', 'push <src path> <dst path>'));
          CmdList.RegisterCommand(
            TChmodCommand.Create('chmod', 'change file/dir mode', 'chmod <mode> <path>'));
          CmdList.RegisterCommand(
            TCorruptCommand.Create('corrupt', 'corrupt file', 'corrupt <path>'));

          for line in script do
            CmdList.ExecuteCommand(line);

        finally
          FreeAndNil(script);
        end;

      end
      else
      begin
        fRCFS.corruptFile(targetFile);
      end;

    finally
      FreeAndNil(fRCFS);
    end;

    Result := 0;
  finally
    FreeAndNil(fStream);
  end;
end;

function TRCFSVMDK.Execute: integer;
var
  fStream: TStream;
  fs: TFileStream;
  reader: TVMDKReader;
  parts: TPartitionArray;
  useVMDK: boolean;
  line, image, _image, scriptName, _scriptName, _vmdk: string;
  i, k: integer;
  buf: TBytes;
  script: TStringList;

  CmdList: ICommandList;
begin
  Result := 1;
  SetLength(parts, 0);
  setLength(Buf, SECTOR_SIZE);

  GetParameterValue('--image', _image);
  GetParameterValue('--script', _scriptName);
  image := ExpandFileName(_image);

  scriptName := ExpandFileName(_scriptName);
  if not FileExists(scriptName) then
  begin
    WriteLn('Script file: "', _scriptName, '" not exists');
    Exit(-1);
  end;

  useVMDK := GetParameterValue('--vmdk', _vmdk);

  reader := nil;
  fs := nil;
  fStream := nil;
  script := nil;
  try
    if useVMDK then
    begin
      fs := TFileStream.Create(image, fmOpenReadWrite or fmShareDenyWrite);
      reader := TVMDKReader.Create(fs);
      if reader.Kind = vkUnknown then
      begin
        Writeln('Error: Unsupported or corrupt VMDK.');
        Exit(3);
      end;

      ListPartitions(reader, parts);
      if Length(parts) = 0 then
      begin
        Writeln('Error: No partitions found.');
        Exit(4);
      end;

      k := -1;
      for i := 0 to high(parts) do
      begin
        if reader.ReadSectors(parts[i].StartLBA, 1, @buf[0]) then
        begin
          if (PDword(@buf[0])^ = $686d6972) and (PQword(@buf[8])^ = $202020736f2d7366) then
          begin
            k := i;
            break;
          end;
        end;
      end;
      if k = -1 then
      begin
        Writeln('Error: rcfs partition not found.');
        Exit(6);
      end;

      // Записувати одразу у пам'ять не обов'язково
      // Використовуємо окремий MemoryStream, якщо потрібно для TRCFS
      fStream := TMemoryStream.Create;
      if not ExtractPartition(reader, parts[1], fStream) then
      begin
        Writeln('Error: Failed to extract partition.');
        Exit(5);
      end;
      fStream.Position := 0;
    end
    else
    begin
      fStream := TFileStream.Create(image, fmOpenReadWrite or fmShareDenyWrite);
    end;

    fRCFS := TRCFS.Create(fStream);
    try

      script := TStringList.Create;
      try
        script.LoadFromFile(scriptName);
        CmdList := TCommandList.Create;
        CmdList.RegisterCommand(
          TPushCommand.Create('push', 'push file to image', 'push <src path> <dst path>'));
        CmdList.RegisterCommand(
          TChmodCommand.Create('chmod', 'change file/dir mode', 'chmod <mode> <path>'));
        CmdList.RegisterCommand(
          TCorruptCommand.Create('corrupt', 'corrupt file', 'corrupt <path>'));

        for line in script do
          CmdList.ExecuteCommand(line);

      finally
        FreeAndNil(script);
      end;

    finally
      FreeAndNil(fRCFS);
    end;

    // Після обробки записуємо назад у VMDK
    if useVMDK then
    begin
      fStream.Position := 0; // повертаємо потік на початок
      if not WritePartition(reader, parts[k], fStream) then
      begin
        Writeln('Error: Failed to write partition back to VMDK.');
        Exit(6);
      end;
    end;

    Result := 0;
  finally
    FreeAndNil(fStream);
    FreeAndNil(reader);
    FreeAndNil(fs);
  end;
end;


function TRCFSExtract.Execute: integer;
var
  image, outPath: string;
  _image, _outPath: string;
  fStream: TFileStream;
  i: integer;
  inode: rcfs_inode;
begin
  GetParameterValue('--image', _image);
  GetParameterValue('--out', _outPath);
  image := ExpandFileName(_image);
  outPath := ExpandFileName(_outPath);


  fStream := TFileStream.Create(image, fmOpenReadWrite or fmShareDenyWrite);
  try
    fRCFS := TRCFS.Create(fStream);
    try
      ForceDirectories(outPath);

      inode := fRCFS.GetInode(1);
      fRCFS.ExtractTree(inode, outPath);

    finally
      FreeAndNil(fRCFS);
    end;


  finally
    FreeAndNil(fstream);
  end;

end;


initialization
  RCFSCommand := TRCFSCommand.Create('rcfs', 'rcfs image operations');

  RCFSModify := TRCFSModify.Create('modify', 'rcfs image modification');
  RCFSModify.AddPathParameter('-c', '--corrupt', 'corrupt file inside rcfs');
  RCFSModify.AddPathParameter('-s', '--script', 'script file');
  RCFSModify.AddPathParameter('-i', '--image', 'RCFS image file', True);

  RCFSExtract := TRCFSExtract.Create('extract', 'extract files from rcfs image');
  RCFSExtract.AddPathParameter('-i', '--image', 'RCFS image file', True);
  RCFSExtract.AddPathParameter('-o', '--out', 'Output path', True);

  RCFSVMDK := TRCFSVMDK.Create('vmdk', 'VMWare disk image manipulation');
  RCFSVMDK.AddPathParameter('-s', '--script', 'script file');
  RCFSVMDK.AddPathParameter('-i', '--image', 'RCFS image file', True);

  RCFScommand.AddSubCommand(RCFSModify);
  RCFScommand.AddSubCommand(RCFSExtract);
  RCFScommand.AddSubCommand(RCFSVMDK);

end.
