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

procedure ExtractLoaders(const FileName, OutputDir: string);
const
  PATTERN: array[0..3] of byte = ($04, $0B, $00, $04);
var
  InFile, OutFile: TFileStream;
  Mem, CompressedData, DecompressedData: TMemoryStream;
  Loaders: array of TLoaderHdr2;
  SectionInfo: TImageSectionHeader;
  ImageBase, VA, RAW, SectionStart, SectionEnd: DWord;
  SearchPos, SearchSize, Count, dscPos: DWord;
  i, j, k: integer;
  OutputFileName, ResultDir: string;
  DataPtr: pbyte;
  SearchRec: TRawbyteSearchRec;
begin
  // Визначаємо директорію результатів
  if OutputDir <> '' then
    ResultDir := IncludeTrailingPathDelimiter(OutputDir) + ChangeFileExt(ExtractFileName(FileName), '')
  else
    ResultDir := ChangeFileExt(ExtractFileName(FileName), '');

  if not FindDataSection(FileName, SectionInfo, ImageBase) then
  begin
    TConsole.WriteLn('Error: can''t find .data section', ccRed);
    Exit;
  end;

  Mem := TMemoryStream.Create;
  try
    InFile := TFileStream.Create(FileName, fmOpenRead);
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

    // Пошук патерну
    for i := 0 to integer(SearchSize) - 12 do
    begin
      if CompareMem(DataPtr + i, @PATTERN[0], 4) then
      begin
        // Перевіряємо контекст
        if PDWord(DataPtr + i - 4)^ = $00070000 then
        begin
          dscPos := SearchPos + DWord(i);
          Count := PDWord(DataPtr + i - 8)^;
          Break;
        end;

        if (PDWord(DataPtr + i - 8)^ = $00070000) and (PDWord(DataPtr + i - 4)^ = 0) then
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
    Mem.Seek(dscPos, soFromBeginning);
    Mem.Read(Loaders[0], Count * SizeOf(TLoaderHdr2));

    // Створюємо директорію для результатів
    if not DirectoryExists(ResultDir) then
      ForceDirectories(ResultDir)
    else
    begin
      // Очищуємо директорію
      if FindFirst(ResultDir + DirectorySeparator + '*', faAnyFile, SearchRec) = 0 then
      begin
        repeat
          if (SearchRec.Name <> '.') and (SearchRec.Name <> '..') then
            DeleteFile(ResultDir + DirectorySeparator + SearchRec.Name);
        until FindNext(SearchRec) <> 0;
        FindClose(SearchRec);
      end;
    end;

    for i := 0 to Count - 1 do
    begin
      if (Loaders[i].loaderPtr >= SectionStart) and (Loaders[i].loaderPtr < SectionEnd) then
      begin
        WriteLn(Format('%.3d [%.8x] %.8x:%.8x-%.8x *', [i, int64(Loaders[i].loaderPtr),
          int64(Loaders[i].deviceID), int64(Loaders[i].RAMstart), int64(Loaders[i].RAMend)]));

        // Генеруємо унікальне ім'я файлу
        j := 0;
        repeat
          OutputFileName := Format('%s%sloader_%.8X-%.2d.bin', [ResultDir,
            DirectorySeparator, int64(Loaders[i].deviceID), j]);
          Inc(j);
        until not FileExists(OutputFileName);

        // Витягуємо і розпаковуємо дані
        k := Loaders[i].loaderPtr + RAW - VA;
        Mem.Seek(k, soFromBeginning);

        CompressedData := TMemoryStream.Create;
        DecompressedData := TMemoryStream.Create;
        try
          CompressedData.CopyFrom(Mem, Min(1024 * 1024, Mem.Size - k));
          if unzipStream(CompressedData, DecompressedData) then
          begin
            OutFile := TFileStream.Create(OutputFileName, fmCreate);
            try
              DecompressedData.Position := 0;
              OutFile.CopyFrom(DecompressedData, DecompressedData.Size);
              TConsole.WriteLn(Format('  Saved: %s (%d bytes)',
                [ExtractFileName(OutputFileName), DecompressedData.Size]));
            finally
              OutFile.Free;
            end;
          end
          else
            TConsole.WriteLn('  Unpack error', ccRed);
        finally
          DecompressedData.Free;
          CompressedData.Free;
        end;
      end
      else
        WriteLn(Format('%.3d [%.8x] %.8x:%.8x-%.8x', [i, int64(Loaders[i].loaderPtr),
          int64(Loaders[i].deviceID), int64(Loaders[i].RAMstart), int64(Loaders[i].RAMend)]));
    end;

    TConsole.WriteLn(Format('Finished. Extracted: %d loaders', [Count]));

  finally
    Mem.Free;
  end;
end;

end.
