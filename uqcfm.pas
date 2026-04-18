unit uQCFM;

{$mode ObjFPC}{$H+}

interface

uses
  Classes,
  SysUtils,
  CLI.Interfaces,    // Core interfaces
  CLI.Command,       // Base command implementation
  CLI.Progress,      // Optional: Progress indicators
  CLI.Console;       // Optional: Colored console output

type
  TPackCommand = class(TBaseCommand)
  public
    function Execute: integer; override;
  end;

type
  TAutoloaderCommand = class(TBaseCommand)
  public
    function Execute: integer; override;
  end;

  TALCreateCommand = class(TBaseCommand)
  public
    function Execute: integer; override;
  end;

  TALExtractCommand = class(TBaseCommand)
  public
    function Execute: integer; override;
  end;

  TALLoadersCommand = class(TBaseCommand)
  public
    function Execute: integer; override;
  end;


  TUnpackCommand = class(TBaseCommand)
  public
    function Execute: integer; override;
  end;


  TSplitCommand = class(TBaseCommand)
  public
    function Execute: integer; override;
  end;


var
  Pack: TPackCommand;
  Unpack: TUnPackCommand;
  Split: TSplitCommand;
  Autoloader: TAutoloaderCommand;
  ALCreate: TALCreateCommand;
  ALExtract: TALExtractCommand;
  ALLoaders: TALLoadersCommand;

implementation

uses qcfm, uInfo, StrUtils, ldr, uMisc, uAutoloader;

var
  pb: IProgressIndicator = nil;

procedure qcfm_callback(fName: string; current, total: int64);
begin
  if Assigned(pb) and (current >= 0) then
  begin
    pb.Update(current);
  end
  else
  begin
    if Assigned(pb) then
    begin
      pb.Stop;
      pb := nil;
    end;
    TConsole.WriteLn('Processing ' + fName);
    pb := CreateProgressBar(total, 40);
    pb.Start;
  end;
end;


function TSplitCommand.Execute: integer;
var
  fileName: string;
begin
  GetParameterValue('--input', fileName);
  if FileExists(fileName) then
  begin
    ExtractBlackBerryAutoloaderFromPE(fileName);
  end;
end;


function TALLoadersCommand.Execute: integer;
var
  fileName, outDir: string;
begin
  GetParameterValue('--input', fileName);
  GetParameterValue('--output', outDir);
  if FileExists(fileName) then
    ExtractLoaders(fileName, outDir);
end;


function TPackCommand.Execute: integer;
var
  mfcqFile, inputList, inputInline, fileName: string;
  vers, files: TStringList;
  i: integer;
  ver: integer;
  tmps: string;
  fast, sign: boolean;
  outFile: TFileStream;
  xxx: TStringArray;
  crc: cardinal;
begin
  Result := 0;
  ver := 0;

  if not GetParameterValue('--container', mfcqFile) then
  begin
    TConsole.WriteLn('Error: qcfm container file is required', ccRed);
    Exit(3);
  end;
  GetParameterValue('--list', inputList);
  GetParameterValue('--input', inputInline);
  sign := GetParameterValue('--sign', tmps);
  fast := GetParameterValue('--fast', tmps);
  if GetParameterValue('--versions', tmps) then
  begin
    vers := TStringList.Create;
    try
      if tmps <> '' then
        vers.AddCommaText(tmps);
      vers.Sorted := True;
      if vers.Find('1', i) then ver := ver + 1;
      if vers.Find('2', i) then ver := ver + 2;
    finally
      FreeAndNil(vers);
    end;
  end;

  files := TStringList.Create;
  try
    // Завантажити список файлів
    if (inputList <> '') and FileExists(ExpandFileName(inputList)) then
      files.LoadFromFile(ExpandFileName(inputList));

    // Додати файли з --input
    if inputInline <> '' then
      files.AddCommaText(inputInline);

    // Очистити список від неіснуючих файлів
    for i := files.Count - 1 downto 0 do
    begin
      xxx := SplitString(files[i], '=');
      fileName := ExpandFileName(xxx[0]);
      if not FileExists(fileName) then
        files.Delete(i);
    end;

    if files.Count = 0 then
    begin
      TConsole.WriteLn('Error: no valid files found to pack', ccRed);
      Exit(4);
    end;

    TConsole.WriteLn('Packing files into container...', ccCyan);
    packMFCQ(mfcqFile, files, @qcfm_callback, ver, fast);
    if sign then
    begin
      outFile := TFileStream.Create(ExpandFileName(mfcqFile), fmOpenReadWrite or fmShareDenyWrite);
      try
        outFile.Position := outFile.Size;
        outFile.WriteBuffer(dummy_signature[0], sizeof(dummy_signature));
        crc := CRC32FromStream(outFile, 0, outFile.Size - 4);
        outFile.Position := outFile.Size - 4;
        outFile.WriteDWord(crc);
      finally
        FreeAndNil(outFile);
      end;
    end;


  finally
    files.Free;
  end;
end;

function TUnpackCommand.Execute: integer;
var
  mfcqFile: TFileName;
begin
  if not GetParameterValue('--container', mfcqFile) then
  begin
    TConsole.WriteLn('Error: qcfm container file is required', ccRed);
    Exit(5);
  end;
  TConsole.WriteLn('Extracting files...', ccCyan);
  unpackMFCQ(mfcqFile, @qcfm_callback);
end;

function TAutoloaderCommand.Execute: integer;
begin

end;

function TALCreateCommand.Execute: integer;
var
  loaderFile, inputList, inputInline, fileName, vers, capexe: string;
  files: TStringList;
  i, ver: integer;
  fast: boolean;
begin
  Result := 0;

  GetParameterValue('--output', loaderFile);
  GetParameterValue('--list', inputList);
  GetParameterValue('--input', inputInline);
  GetParameterValue('--cap', capexe);
  GetParameterValue('--ver', vers);
  ver := StrToIntDef(vers, 2);

  files := TStringList.Create;
  try
    // Завантажити список файлів
    if (inputList <> '') and FileExists(ExpandFileName(inputList)) then
      files.LoadFromFile(ExpandFileName(inputList));

    // Додати файли з --input
    if inputInline <> '' then
      files.AddCommaText(inputInline);

    // Очистити список від неіснуючих файлів
    for i := files.Count - 1 downto 0 do
    begin
      fileName := ExpandFileName(files[i]);
      if FileExists(fileName) then
        files[i] := fileName
      else
        files.Delete(i);
    end;

    if files.Count = 0 then
    begin
      TConsole.WriteLn('Error: no valid files found to pack', ccRed);
      Exit(4);
    end;

    TConsole.WriteLn('Packing files into autoloader...', ccCyan);
    if not MakeAutoloader(loaderFile, files, capexe, ver) then
      TConsole.WriteLn('Error: cap.exe is not valid PE file', ccRed);


  finally
    files.Free;
  end;
end;

function TALExtractCommand.Execute: integer;
var
  loaderFile, capexe: string;
begin
  Result := 0;

  if not GetParameterValue('--input', loaderFile) then
  begin
    begin
      TConsole.WriteLn('Error: autoloader.exe file is required', ccRed);
      Exit(5);
    end;

  end;
  GetParameterValue('--cap', capexe);

  TConsole.WriteLn('Extracting cap.exe ...', ccCyan);
  if not ExtractCap(loaderFile, capexe) then
    TConsole.WriteLn('Error: ' + loaderFile + ' is not valid PE file', ccRed);

end;


initialization
  Pack := TPackCommand.Create('pack', 'pack file into qcfm container');
  Pack.AddPathParameter('-c', '--container', 'container file', True);
  Pack.AddArrayParameter('-i', '--input', 'input files');
  Pack.AddPathParameter('-l', '--list', 'input files list');
  Pack.AddArrayParameter('-v', '--versions', 'QCFM versions', False, '2');
  Pack.AddFlag('-s', '--sign', 'add fake signature');
  Pack.AddFlag('-f', '--fast', 'include empty blocks');

  UnPack := TUnPackCommand.Create('unpack', 'extract files from qcfm container');
  UnPack.AddPathParameter('-c', '--container', 'container file', True);

  Split := TSplitCommand.Create('split', 'Split autoloader');
  Split.AddPathParameter('-i', '--input', 'input files', True);

  ALCreate := TALCreateCommand.Create('create', 'Create autoloader ');
  ALCreate.AddPathParameter('-o', '--output', 'Autoloader file', False, 'autoloader.exe');
  ALCreate.AddPathParameter('-c', '--cap', 'own cap.exe file', False, 'cap.exe');
  ALCreate.AddArrayParameter('-i', '--input', 'input files');
  ALCreate.AddPathParameter('-l', '--list', 'input files list');
  ALCreate.AddIntegerParameter('-v', '--ver', 'cap tail version', False, '2');

  ALExtract := TALExtractCommand.Create('extract', 'Extract cap.exe from autoloader');
  ALExtract.AddPathParameter('-i', '--input', 'Autoloader file', True);
  ALExtract.AddPathParameter('-c', '--cap', 'own cap.exe file', False, 'cap.exe');

  ALLoaders := TALLoadersCommand.Create('loaders', 'Extract RAM-loaders from CAP, CFP, autoloaders');
  ALLoaders.AddPathParameter('-i', '--input', 'cap.exe/cfp.exe file', True);
  ALLoaders.AddPathParameter('-o', '--output', 'output dir', False, 'ramloaders');

  AutoLoader := TAutoLoaderCommand.Create('autoloader', 'Autoloader manipulations');

  AutoLoader.AddSubCommand(ALCreate);
  AutoLoader.AddSubCommand(ALExtract);
  AutoLoader.AddSubCommand(ALLoaders);

end.
