unit PEFile;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, Math;

type
  TImageDosHeader = packed record
    e_magic: word;
    e_cblp: word;
    e_cp: word;
    e_crlc: word;
    e_cparhdr: word;
    e_minalloc: word;
    e_maxalloc: word;
    e_ss: word;
    e_sp: word;
    e_csum: word;
    e_ip: word;
    e_cs: word;
    e_lfarlc: word;
    e_ovno: word;
    e_res: array[0..3] of word;
    e_oemid: word;
    e_oeminfo: word;
    e_res2: array[0..9] of word;
    e_lfanew: DWord;
  end;

  TImageFileHeader = packed record
    Machine: word;
    NumberOfSections: word;
    TimeDateStamp: DWord;
    PointerToSymbolTable: DWord;
    NumberOfSymbols: DWord;
    SizeOfOptionalHeader: word;
    Characteristics: word;
  end;

  TImageOptionalHeader32 = packed record
    Magic: word;
    MajorLinkerVersion: byte;
    MinorLinkerVersion: byte;
    SizeOfCode: DWord;
    SizeOfInitializedData: DWord;
    SizeOfUninitializedData: DWord;
    AddressOfEntryPoint: DWord;
    BaseOfCode: DWord;
    BaseOfData: DWord;
    ImageBase: DWord;
    SectionAlignment: DWord;
    FileAlignment: DWord;
    MajorOperatingSystemVersion: word;
    MinorOperatingSystemVersion: word;
    MajorImageVersion: word;
    MinorImageVersion: word;
    MajorSubsystemVersion: word;
    MinorSubsystemVersion: word;
    Win32VersionValue: DWord;
    SizeOfImage: DWord;
    SizeOfHeaders: DWord;
    CheckSum: DWord;
    Subsystem: word;
    DllCharacteristics: word;
    SizeOfStackReserve: DWord;
    SizeOfStackCommit: DWord;
    SizeOfHeapReserve: DWord;
    SizeOfHeapCommit: DWord;
    LoaderFlags: DWord;
    NumberOfRvaAndSizes: DWord;
  end;

  TImageSectionHeader = packed record
    Name: array[0..7] of ansichar;
    VirtualSize: DWord;
    VirtualAddress: DWord;
    SizeOfRawData: DWord;
    PointerToRawData: DWord;
    PointerToRelocations: DWord;
    PointerToLinenumbers: DWord;
    NumberOfRelocations: word;
    NumberOfLinenumbers: word;
    Characteristics: DWord;
  end;

// Знаходить секцію .data в PE файлі
function FindDataSection(const FileName: string; out SectionInfo: TImageSectionHeader;
  out ImageBase: DWord): boolean;

// Отримує зміщення кінця PE файлу
function GetPEEndOffset(const Stream: TStream): int64;

implementation

const
  IMAGE_DOS_SIGNATURE = $5A4D; // "MZ"
  IMAGE_NT_SIGNATURE = $00004550; // "PE\0\0"

function ValidatePEHeaders(Stream: TStream; out DosHeader: TImageDosHeader;
  out FileHeader: TImageFileHeader): boolean;
var
  Signature: DWord;
begin
  Result := False;
  Stream.Position := 0;

  // Читаємо DOS заголовок
  if Stream.Read(DosHeader, SizeOf(DosHeader)) <> SizeOf(DosHeader) then Exit;
  if DosHeader.e_magic <> IMAGE_DOS_SIGNATURE then Exit;

  // Перевіряємо валідність зміщення PE заголовку
  if (DosHeader.e_lfanew = 0) or (DosHeader.e_lfanew >= Stream.Size - 4) then Exit;

  // Переходимо до PE заголовку і перевіряємо сигнатуру
  Stream.Position := DosHeader.e_lfanew;
  if Stream.Read(Signature, SizeOf(Signature)) <> SizeOf(Signature) then Exit;
  if Signature <> IMAGE_NT_SIGNATURE then Exit;

  // Читаємо файловий заголовок
  if Stream.Read(FileHeader, SizeOf(FileHeader)) <> SizeOf(FileHeader) then Exit;

  Result := True;
end;

function FindDataSection(const FileName: string; out SectionInfo: TImageSectionHeader;
  out ImageBase: DWord): boolean;
var
  Stream: TFileStream;
  DosHeader: TImageDosHeader;
  FileHeader: TImageFileHeader;
  OptionalHeader: TImageOptionalHeader32;
  Section: TImageSectionHeader;
  I: integer;
  SectionName: string;
begin
  Result := False;
  ImageBase := 0;

  try
    Stream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
    try
      // Валідуємо PE заголовки
      if not ValidatePEHeaders(Stream, DosHeader, FileHeader) then Exit;

      // Читаємо опціональний заголовок
      if Stream.Read(OptionalHeader, SizeOf(OptionalHeader)) <> SizeOf(OptionalHeader) then Exit;
      ImageBase := OptionalHeader.ImageBase;

      // Пропускаємо решту опціонального заголовку, якщо він більший
      if FileHeader.SizeOfOptionalHeader > SizeOf(OptionalHeader) then
        Stream.Position := Stream.Position + (FileHeader.SizeOfOptionalHeader - SizeOf(OptionalHeader));

      // Шукаємо секцію .data
      for I := 0 to FileHeader.NumberOfSections - 1 do
      begin
        if Stream.Read(Section, SizeOf(Section)) <> SizeOf(Section) then Exit;

        SetString(SectionName, PChar(@Section.Name[0]), 8);
        SectionName := Trim(SectionName); // Прибираємо null-символи та пробіли

        if SectionName = '.data' then
        begin
          SectionInfo := Section;
          Result := True;
          Exit;
        end;
      end;
    finally
      Stream.Free;
    end;
  except
    // Ігноруємо помилки доступу до файлу
    Result := False;
  end;
end;

function GetPEEndOffset(const Stream: TStream): int64;
var
  DosHeader: TImageDosHeader;
  FileHeader: TImageFileHeader;
  OptionalHeaderMagic: word;
  Section: TImageSectionHeader;
  I: integer;
  MaxOffset: int64;
begin
  Result := 0;

  // Валідуємо PE заголовки
  if not ValidatePEHeaders(Stream, DosHeader, FileHeader) then Exit;

  // Читаємо magic опціонального заголовку
  if Stream.Read(OptionalHeaderMagic, SizeOf(OptionalHeaderMagic)) <> SizeOf(OptionalHeaderMagic) then Exit;

  // Пропускаємо решту опціонального заголовку
  Stream.Position := Stream.Position + FileHeader.SizeOfOptionalHeader - SizeOf(OptionalHeaderMagic);

  MaxOffset := 0;

  // Читаємо заголовки секцій
  for I := 0 to FileHeader.NumberOfSections - 1 do
  begin
    if Stream.Read(Section, SizeOf(Section)) <> SizeOf(Section) then Break;

    // Перевіряємо валідність секції
    if (Section.PointerToRawData > 0) and (Section.SizeOfRawData > 0) then
    begin
      MaxOffset := Max(MaxOffset, int64(Section.PointerToRawData) + Section.SizeOfRawData);
    end;
  end;

  // Обмежуємо розміром файлу
  Result := Min(MaxOffset, Stream.Size);
end;

end.
