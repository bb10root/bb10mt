unit uBatch;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils,
  CLI.Command,
  CLI.Interfaces,
  CLI.Progress,
  CLI.Console;

type
  TBatchCommand = class(TBaseCommand)
  public
    function Execute: integer; override;
  end;

var
  BatchCmd: TBatchCommand;

implementation

uses uAutoloader, qcfm, FileUtil, scripthandler, StrUtils, uMisc, qnx6;

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

procedure CleanupProgressBar;
begin
  if Assigned(pb) then
  begin
    pb.Stop;
    pb := nil;
  end;
end;

function TBatchCommand.Execute: integer;
const
  SIZE_THRESHOLD = 100 * 1024 * 1024;
  REQUIRED_SPACE_RATIO = 4;
var
  compact: boolean = False;
  mfcqFile, os_bundle, radio_bundle: string;
  loaderFile, fileName, inputList: string;
  input, outDir, script, tmps, imagePath: string;
  files, FileList: TStringList;
  fSize: int64;
  i: integer;
  xxx: TStringArray;
  crc: cardinal;
  fs, outFile: TFileStream;
  qnx6: TQNX6Fs;
  inputSize, freeSpace: int64;
  checkPath: string;

  cap: TPEAutoloaderHeaderInfo;
begin
  Result := 0;
  os_bundle := '';
  radio_bundle := '';

  GetParameterValue('--input', input);
  input := ExpandFileName(input);

  if GetParameterValue('--output', outDir) then
    outDir := ExpandFileName(outDir)
  else
    outDir := CreateTempDir;

  GetParameterValue('--script', script);
  script := ExpandFileName(script);

  if GetParameterValue('--compact', tmps) then
    compact := StrToBoolDef(tmps, False);

  if not FileExists(input) then
  begin
    TConsole.WriteLn('Error: Input file does not exist: ' + input, ccRed);
    Exit(1);
  end;

  // --- Кросплатформена перевірка вільного місця ---
  inputSize := FileSize(input);

  // Для перевірки беремо виснуючу директорію (якщо outDir ще не створено)
  checkPath := outDir;
  while (checkPath <> '') and not DirectoryExists(checkPath) do
    checkPath := ExtractFilePath(ExcludeTrailingPathDelimiter(checkPath));

  if checkPath = '' then
    checkPath := GetCurrentDir;

  freeSpace := GetPathFreeSpace(checkPath);

  if (freeSpace <> -1) and (freeSpace < inputSize * REQUIRED_SPACE_RATIO) then
  begin
    TConsole.WriteLn(Format('Error: Insufficient disk space on target partition (%s).',
      [checkPath]), ccRed);
    TConsole.WriteLn(Format('Required: %d MB, Available: %d MB',
      [(inputSize * REQUIRED_SPACE_RATIO) div (1024 * 1024), freeSpace div (1024 * 1024)]), ccRed);
    Exit(3);
  end;
  // ------------------------------------------------

  ExtractBlackBerryAutoloaderFromPE(input, outDir);

  // 1. Пошук bundles
  FileList := FindAllFiles(outDir, '*.signed', False);
  try
    for tmps in FileList do
    begin
      fSize := FileSize(tmps);
      if fSize < 0 then Continue;

      if fSize >= SIZE_THRESHOLD then
        os_bundle := tmps
      else
        radio_bundle := tmps;
    end;

    if os_bundle <> '' then
      TConsole.WriteLn(Format('OS Bundle: %s (%d bytes)', [os_bundle, FileSize(os_bundle)]))
    else
      TConsole.WriteLn('OS Bundle not found!', ccRed);

    if radio_bundle <> '' then
      TConsole.WriteLn(Format('Radio Bundle: %s (%d bytes)', [radio_bundle, FileSize(radio_bundle)]))
    else
      TConsole.WriteLn('Radio Bundle not found!', ccRed);
  finally
    FreeAndNil(FileList);
  end;

  if os_bundle = '' then
  begin
    TConsole.WriteLn('Error: Cannot proceed without OS Bundle', ccRed);
    Exit(2);
  end;

  // 2. Розпакування MFCQ та пошук .ufs
  try
    unpackMFCQ(ExpandFileName(os_bundle), @qcfm_callback, outDir);
  finally
    CleanupProgressBar;
  end;

  FileList := FindAllFiles(outDir, '*.ufs', False);
  try
    if FileList.Count <> 1 then
    begin
      TConsole.WriteLn('Error: No UFS file found (or multiple found)', ccRed);
      Exit(-1);
    end;
    imagePath := ExpandFileName(FileList.Strings[0]);
  finally
    FreeAndNil(FileList);
  end;

  // 3. Запуск скрипта модифікації
  runScript(imagePath, script);

  // 3.1. Компактизація образу QNX6
  if compact then
  begin
    TConsole.WriteLn('Opening image for compaction: ' + imagePath, ccCyan);
    fs := TFileStream.Create(imagePath, fmOpenReadWrite or fmShareDenyWrite);
    try
      qnx6 := TQNX6Fs.Create(fs);
      try
        try
          qnx6.Open(True);
          TConsole.WriteLn('Starting block compaction...');
          qnx6.CompactBlocks;
          qnx6.Flush;
          TConsole.WriteLn('Filesystem compaction completed successfully.');
        except
          on E: Exception do
          begin
            TConsole.WriteLn('Fatal error during compaction: ' + E.Message, ccRed);
            Exit(2);
          end;
        end;
      finally
        FreeAndNil(qnx6);
      end;
    finally
      FreeAndNil(fs);
    end;
  end;

  // Пошук .lst списку
  FileList := FindAllFiles(outDir, '*.lst', False);
  try
    if FileList.Count <> 1 then
    begin
      TConsole.WriteLn('Error: No lst file found (or multiple found)', ccRed);
      Exit(-1);
    end;
    inputList := ExpandFileName(FileList.Strings[0]);
  finally
    FreeAndNil(FileList);
  end;

  // 4. Пакування модифікованих файлів
  files := TStringList.Create;
  try
    if (inputList <> '') and FileExists(inputList) then
      files.LoadFromFile(inputList);

    files.BeginUpdate;
    try
      for i := files.Count - 1 downto 0 do
      begin
        xxx := SplitString(files[i], '=');
        fileName := ExpandFileName(IncludeTrailingPathDelimiter(outDir) + xxx[0]);

        if not FileExists(fileName) then
        begin
          files.Delete(i);
          Continue;
        end;

        if Length(xxx) >= 2 then
          files[i] := fileName + '=' + xxx[1]
        else
          files[i] := fileName;
      end;
    finally
      files.EndUpdate;
    end;

    if files.Count = 0 then
    begin
      TConsole.WriteLn('Error: no valid files found to pack', ccRed);
      Exit(4);
    end;

    mfcqFile := ChangeFileExt(os_bundle, '.unsigned');
    TConsole.WriteLn('Packing files into container...', ccCyan);

    try
      packMFCQ(mfcqFile, files, @qcfm_callback, 2, False);
    finally
      CleanupProgressBar;
    end;

    outFile := TFileStream.Create(mfcqFile, fmOpenReadWrite or fmShareDenyWrite);
    try
      outFile.Seek(0, soEnd);
      outFile.Write(signature_data[0], Length(signature_data));
      crc := CRC32FromStream(outFile, 0, outFile.Size - 4);
      outFile.Seek(-4, soEnd);
      outFile.WriteDWord(crc);
    finally
      FreeAndNil(outFile);
    end;
  finally
    FreeAndNil(files);
  end;

  // 5. Створення фінального autoloader
  files := TStringList.Create;
  try
    files.Add(mfcqFile);
    TConsole.WriteLn('Packing files into OS autoloader...', ccCyan);
    loaderFile := IncludeTrailingPathDelimiter(outDir) + ExtractFileName(ChangeFileExt(input, '_os.exe'));

    if not RebuildAutoloader(input, loaderFile, files) then
    begin
      TConsole.WriteLn('Error: Failed to build moded autoloader executable', ccRed);
      Exit(5);
    end;

    files.Clear;
    files.Add(radio_bundle);
    TConsole.WriteLn('Packing files into Radio autoloader...', ccCyan);
    loaderFile := IncludeTrailingPathDelimiter(outDir) + ExtractFileName(ChangeFileExt(input, '_radio.exe'));
    if not RebuildAutoloader(input, loaderFile, files) then
    begin
      TConsole.WriteLn('Error: Failed to build radio autoloader executable', ccRed);
      Exit(5);
    end;
  finally
    FreeAndNil(files);
  end;
end;

initialization

  BatchCmd := TBatchCommand.Create('batch', 'Auto autoloader processing');
  BatchCmd.AddPathParameter('-i', '--input', 'autoloader file', True);
  BatchCmd.AddPathParameter('-s', '--script', 'script file', True);
  BatchCmd.AddPathParameter('-o', '--output', 'output folder');
  BatchCmd.AddFlag('-c', '--compact', 'compact image');

end.
