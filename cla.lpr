program CreateLoaderArchive;

{$mode ObjFPC}{$H+}

uses
  Classes, SysUtils, IniFiles, StrUtils, uArchive;

procedure FindAllFiles(FileList: TStrings; const StartDir, SearchMask: string; Recursive: Boolean);
var
  SearchRec: TSearchRec;
  Res: Integer;
  Path: string;
begin
  Path := IncludeTrailingPathDelimiter(StartDir);

  // Шукаємо файли
  Res := FindFirst(Path + SearchMask, faAnyFile and not faDirectory, SearchRec);
  try
    while Res = 0 do
    begin
      FileList.Add(Path + SearchRec.Name);
      Res := FindNext(SearchRec);
    end;
  finally
    FindClose(SearchRec);
  end;

  if Recursive then
  begin
    // Шукаємо папки для рекурсії
    Res := FindFirst(Path + '*', faDirectory, SearchRec);
    try
      while Res = 0 do
      begin
        if (SearchRec.Name <> '.') and (SearchRec.Name <> '..') then
        begin
          if (SearchRec.Attr and faDirectory) <> 0 then
            FindAllFiles(FileList, Path + SearchRec.Name, SearchMask, True);
        end;
        Res := FindNext(SearchRec);
      end;
    finally
      FindClose(SearchRec);
    end;
  end;
end;

procedure ProcessLoaders(const SrcDir, IniFileName, ArcFileName: string);
var
  ArcStream: TFileStream;
  ArcWriter: TMyArcWriter;
  Ini: TIniFile;
  Files: TStringList;
  i: integer;
  FileName, BaseName, LoaderID, LdrName: string;
  CRCList: array of cardinal;
  UniqueFiles: TStringList;
  FileStream: TFileStream;
  CRC, FoundCRC: cardinal;
  idxUnique: integer;
  LdrCount: integer;

  function ExtractLoaderID(const FN: string): string;
  var
    // Витягти 8-значний hex (приклад: loader_04000E04-00.bin -> 04000E04)
    s: string;
    dashPos: integer;
  begin
    Result := '';
    s := LowerCase(FN);
    if Pos('loader_', s) = 1 then
    begin
      dashPos := Pos('-', s);
      if (dashPos > 0) and (Length(s) >= dashPos + 1) then
        Result := Copy(s, 8, dashPos - 8); // відразу після 'loader_' до '-'
    end;
  end;

begin
  Files := TStringList.Create;
  UniqueFiles := TStringList.Create;
  Ini := TIniFile.Create(IniFileName);
  try
    // Знайти всі файли loader_*.bin в каталозі (без підкаталогів)
    FindAllFiles(Files, SrcDir, 'loader_*.bin', False);

    ArcStream := TFileStream.Create(ArcFileName, fmCreate);
    try
      ArcWriter := TMyArcWriter.Create(ArcStream);
      try
        ArcWriter.SetLzmaOptions(TMyArcWriter.DefaultLzmaOptions);

        SetLength(CRCList, 0);
        LdrCount := 0;

        for i := 0 to Files.Count - 1 do
        begin
          FileName := Files[i];
          BaseName := ExtractFileName(FileName);
          LoaderID := ExtractLoaderID(BaseName);
          if LoaderID = '' then
          begin
            Writeln('Пропущено файл (не підходить шаблон): ', BaseName);
            Continue;
          end;

          FileStream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
          try
            CRC := ComputeStreamCRC32(FileStream);
            // Перевірка унікальності через CRC
            FoundCRC := 0;
            idxUnique := -1;
            for idxUnique := 0 to Length(CRCList) - 1 do
            begin
              if CRCList[idxUnique] = CRC then
              begin
                FoundCRC := idxUnique + 1;
                Break;
              end;
            end;

            if FoundCRC = 0 then
            begin
              // Новий унікальний файл
              Inc(LdrCount);
              SetLength(CRCList, LdrCount);
              CRCList[LdrCount - 1] := CRC;

              LdrName := Format('LDR_%2.2d', [LdrCount - 1]);
              // Додати файл у архів
              FileStream.Position := 0;
              ArcWriter.AddFileFromStream(LdrName, FileStream);

              // Записати у ini: 04000E04=LDR_XX
              Ini.WriteString('Loaders', LoaderID, LdrName);
              Writeln('Додано ', BaseName, ' як ', LdrName);
            end
            else
            begin
              // Файл дублікат, беремо існуюче ім'я LDR
              LdrName := Format('LDR_%2.2d', [FoundCRC - 1]);
              Ini.WriteString('Loaders', LoaderID, LdrName);
              Writeln('Пропущено (дублікат) ', BaseName, ' прив’язано до ', LdrName);
            end;
          finally
            FileStream.Free;
          end;
        end;

        ArcWriter.Finalize;
        Ini.UpdateFile;
      finally
        ArcWriter.Free;
      end;
    finally
      ArcStream.Free;
    end;

  finally
    Files.Free;
    UniqueFiles.Free;
    Ini.Free;
  end;
end;

begin
  if ParamCount < 3 then
  begin
    Writeln('Використання: CreateLoaderArchive <srcdir> <ini-file> <archive-file>');
    Exit;
  end;

  try
    ProcessLoaders(ParamStr(1), ParamStr(2), ParamStr(3));
    Writeln('Архів створено успішно');
  except
    on E: Exception do
      Writeln('Помилка: ', E.Message);
  end;
end.

