unit ldr;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils;

procedure ExtractLoaders(const FileName, OutputDir: string);

implementation

uses PEFile, GZIPUtils, FileUtil, Math, CLI.Console;

type
  TLoaderHdr2 = packed record
    deviceID: DWord;
    unk1, unk2, unk3: DWord;
    loaderPtr: DWord;
    loaderSize: DWord;
    ROMstart, ROMend: DWord;
    RAMstart, RAMend: DWord;
    unk4, unk5: DWord;
  end;

procedure ClearDirectory(const Dir: string);
var
  FileInfo: TSearchRec;
begin
  if FindFirst(IncludeTrailingPathDelimiter(Dir) + '*', faAnyFile, FileInfo) = 0 then
  begin
    try
      repeat
        if (FileInfo.Name <> '.') and (FileInfo.Name <> '..') then
          DeleteFile(IncludeTrailingPathDelimiter(Dir) + FileInfo.Name);
      until FindNext(FileInfo) <> 0;
    finally
      FindClose(FileInfo);
    end;
  end;
end;

procedure ExtractLoaders(const FileName, OutputDir: string);
const
  PATTERN: array[0..3] of byte = ($04, $0B, $00, $04);
var
  InFile: TFileStream;
  Mem, CompressedData, DecompressedData: TMemoryStream;
  Loaders: array of TLoaderHdr2;
  SectionInfo: TImageSectionHeader;
  ImageBase: QWord;
  VA, RAW, SectionStart, SectionEnd: DWord;
  SearchPos, SearchSize, Count, dscPos: DWord;
  i, j, k: integer;
  OutputFileName, ResultDir: string;
  DataPtr: pbyte;
begin
  // Визначаємо директорію результатів
  if OutputDir <> '' then
    ResultDir := IncludeTrailingPathDelimiter(OutputDir) +
      ChangeFileExt(ExtractFileName(FileName), '')
  else
    ResultDir := ChangeFileExt(ExtractFileName(FileName), '');

  if not FindDataSection(FileName, SectionInfo, ImageBase) then
  begin
    TConsole.WriteLn('Error: can''t find .data section', ccRed);
    Exit;
  end;

  Mem := TMemoryStream.Create;
  try
    InFile := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
    try
      Mem.CopyFrom(InFile, InFile.Size);
    finally
      InFile.Free;
    end;

    VA := SectionInfo.VirtualAddress + ImageBase;
    SectionStart := VA;
    SearchPos := SectionInfo.PointerToRawData;
    SearchSize := SectionInfo.SizeOfRawData;
    SectionEnd := SectionStart + SearchSize;
    RAW := SectionInfo.PointerToRawData;

    TConsole.WriteLn('Find pattern in .data section...');
    TConsole.WriteLn(Format('VA: $%.8X, RAW: $%.8X, Size: %d', [VA, RAW, SearchSize]));

    Count := 0;
    dscPos := 0;
    DataPtr := pbyte(Mem.Memory) + SearchPos;

    // Пошук патерну з перевіркою безпеки меж пам'яті
    for i := 0 to integer(SearchSize) - 12 do
    begin
      if CompareMem(DataPtr + i, @PATTERN[0], SizeOf(PATTERN)) then
      begin
        // Перевіряємо контекст (з безпечною перевіркою від'ємного зсуву)
        if (i >= 4) and (PDWord(DataPtr + i - 4)^ = $00070000) then
        begin
          dscPos := SearchPos + DWord(i);
          if i >= 8 then
            Count := PDWord(DataPtr + i - 8)^;
          Break;
        end;

        if (i >= 12) and (PDWord(DataPtr + i - 8)^ = $00070000) and
          (PDWord(DataPtr + i - 4)^ = 0) then
        begin
          dscPos := SearchPos + DWord(i);
          Count := PDWord(DataPtr + i - 12)^;
          Break;
        end;
      end;
    end;

    if dscPos = 0 then
    begin
      TConsole.WriteLn('Error: can''t find loaders', ccRed);
      Exit;
    end;

    TConsole.WriteLn(Format('Found %d loaders at position $%.8X', [Count, dscPos]));
    TConsole.WriteLn(Format('Results will be saved into: %s', [ResultDir]));

    SetLength(Loaders, Count);
    Mem.Position := dscPos;
    Mem.ReadBuffer(Loaders[0], Count * SizeOf(TLoaderHdr2));

    // Створюємо або очищуємо директорію для результатів
    if not DirectoryExists(ResultDir) then
      ForceDirectories(ResultDir)
    else
      ClearDirectory(ResultDir);

    // Оптимізація: Виносимо об'єкти потоків за межі циклу
    CompressedData := TMemoryStream.Create;
    DecompressedData := TMemoryStream.Create;
    try
      for i := 0 to Count - 1 do
      begin
        if (Loaders[i].loaderPtr >= SectionStart) and
          (Loaders[i].loaderPtr < SectionEnd) then
        begin
          TConsole.WriteLn(Format('%.3d [%.8X] %.8X:%.8X-%.8X *',
            [i, Loaders[i].loaderPtr, Loaders[i].deviceID, Loaders[i].RAMstart,
            Loaders[i].RAMend]));

          // Генеруємо унікальне ім'я файлу
          j := 0;
          repeat
            OutputFileName := Format('%s%sloader_%.8X-%.2d.bin',
              [ResultDir, DirectorySeparator, Loaders[i].deviceID, j]);
            Inc(j);
          until not FileExists(OutputFileName);

          // Витягуємо і розпаковуємо дані
          k := Loaders[i].loaderPtr + RAW - VA;
          Mem.Position := k;

          CompressedData.Clear;
          DecompressedData.Clear;

          CompressedData.CopyFrom(Mem, Min(1024 * 1024, Mem.Size - k));
          CompressedData.Position := 0;

          if unzipStream(CompressedData, DecompressedData) then
          begin
            DecompressedData.SaveToFile(OutputFileName);
            TConsole.WriteLn(Format('  Saved: %s (%d bytes)',
              [ExtractFileName(OutputFileName), DecompressedData.Size]));
          end
          else
            TConsole.WriteLn('  Unpack error', ccRed);
        end
        else
          TConsole.WriteLn(Format('%.3d [%.8X] %.8X:%.8X-%.8X',
            [i, Loaders[i].loaderPtr, Loaders[i].deviceID, Loaders[i].RAMstart,
            Loaders[i].RAMend]));
      end;
    finally
      DecompressedData.Free;
      CompressedData.Free;
    end;

    TConsole.WriteLn(Format('Finished. Extracted: %d loaders', [Count]));

  finally
    Mem.Free;
  end;
end;

end.
