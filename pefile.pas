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

  TImageOptionalHeader64 = packed record
    Magic: word;
    MajorLinkerVersion: byte;
    MinorLinkerVersion: byte;
    SizeOfCode: DWord;
    SizeOfInitializedData: DWord;
    SizeOfUninitializedData: DWord;
    AddressOfEntryPoint: DWord;
    BaseOfCode: DWord;
    ImageBase: QWord;
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
    SizeOfStackReserve: QWord;
    SizeOfStackCommit: QWord;
    SizeOfHeapReserve: QWord;
    SizeOfHeapCommit: QWord;
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

// Знаходить секцію .data в PE файлі (підтримує PE32 та PE32+)
function FindDataSection(const FileName: string; out SectionInfo: TImageSectionHeader;
  out ImageBase: QWord): boolean;

// Отримує зміщення кінця PE файлу
function GetPEEndOffset(const Stream: TStream): int64;

implementation

const
  IMAGE_DOS_SIGNATURE = $5A4D; // "MZ"
  IMAGE_NT_SIGNATURE = $00004550; // "PE\0\0"
  IMAGE_NT_OPTIONAL_HDR32_MAGIC = $010B;
  IMAGE_NT_OPTIONAL_HDR64_MAGIC = $020B;

function CleanSectionName(const RawName: array of ansichar): string;
var
  I: integer;
begin
  Result := '';
  for I := 0 to Low(RawName) + 7 do
  begin
    if (I > High(RawName)) or (RawName[I] = #0) then Break;
    Result := Result + RawName[I];
  end;
  Result := Trim(Result);
end;

function ValidatePEHeaders(Stream: TStream; out DosHeader: TImageDosHeader;
  out FileHeader: TImageFileHeader; out OptHeaderOffset: int64): boolean;
var
  Signature: DWord;
begin
  Result := False;
  OptHeaderOffset := 0;

  if Stream.Size < SizeOf(TImageDosHeader) then Exit;

  Stream.Position := 0;
  if Stream.Read(DosHeader, SizeOf(DosHeader)) <> SizeOf(DosHeader) then Exit;
  if DosHeader.e_magic <> IMAGE_DOS_SIGNATURE then Exit;

  if (DosHeader.e_lfanew = 0) or (DosHeader.e_lfanew >= Stream.Size -
    SizeOf(Signature) - SizeOf(FileHeader)) then Exit;

  Stream.Position := DosHeader.e_lfanew;
  if Stream.Read(Signature, SizeOf(Signature)) <> SizeOf(Signature) then Exit;
  if Signature <> IMAGE_NT_SIGNATURE then Exit;

  if Stream.Read(FileHeader, SizeOf(FileHeader)) <> SizeOf(FileHeader) then Exit;

  OptHeaderOffset := Stream.Position;
  Result := True;
end;

function FindDataSection(const FileName: string; out SectionInfo: TImageSectionHeader;
  out ImageBase: QWord): boolean;
var
  Stream: TFileStream;
  DosHeader: TImageDosHeader;
  FileHeader: TImageFileHeader;
  OptHeaderOffset: int64;
  Magic: word;
  Opt32: TImageOptionalHeader32;
  Opt64: TImageOptionalHeader64;
  Section: TImageSectionHeader;
  I: integer;
  SectionName: string;
  FirstSectionPos: int64;
begin
  Result := False;
  ImageBase := 0;

  try
    Stream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
    try
      if not ValidatePEHeaders(Stream, DosHeader, FileHeader, OptHeaderOffset) then Exit;

      // Перевіряємо архітектуру через Magic в OptionalHeader
      if Stream.Read(Magic, SizeOf(Magic)) <> SizeOf(Magic) then Exit;
      Stream.Position := OptHeaderOffset;

      if Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC then
      begin
        if Stream.Read(Opt32, SizeOf(Opt32)) <> SizeOf(Opt32) then Exit;
        ImageBase := Opt32.ImageBase;
      end
      else if Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC then
      begin
        if Stream.Read(Opt64, SizeOf(Opt64)) <> SizeOf(Opt64) then Exit;
        ImageBase := Opt64.ImageBase;
      end
      else
        Exit; // Невідомий формат заголовка

      // Вираховуємо точну позицію першої секції за SizeOfOptionalHeader
      FirstSectionPos := OptHeaderOffset + FileHeader.SizeOfOptionalHeader;
      Stream.Position := FirstSectionPos;

      // Пошук секції .data
      for I := 0 to FileHeader.NumberOfSections - 1 do
      begin
        if Stream.Position + SizeOf(Section) > Stream.Size then Exit;
        if Stream.Read(Section, SizeOf(Section)) <> SizeOf(Section) then Exit;

        SectionName := CleanSectionName(Section.Name);
        if SameText(SectionName, '.data') then
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
    Result := False;
  end;
end;

function GetPEEndOffset(const Stream: TStream): int64;
var
  DosHeader: TImageDosHeader;
  FileHeader: TImageFileHeader;
  OptHeaderOffset, FirstSectionPos: int64;
  Section: TImageSectionHeader;
  I: integer;
  MaxOffset: int64;
begin
  Result := 0;

  if not ValidatePEHeaders(Stream, DosHeader, FileHeader, OptHeaderOffset) then Exit;

  FirstSectionPos := OptHeaderOffset + FileHeader.SizeOfOptionalHeader;
  Stream.Position := FirstSectionPos;

  MaxOffset := FirstSectionPos;

  for I := 0 to FileHeader.NumberOfSections - 1 do
  begin
    if Stream.Position + SizeOf(Section) > Stream.Size then Break;
    if Stream.Read(Section, SizeOf(Section)) <> SizeOf(Section) then Break;

    // Перевірка реального розташування даних секції в файлі
    if (Section.PointerToRawData > 0) and (Section.SizeOfRawData > 0) then
    begin
      MaxOffset := Max(MaxOffset, int64(Section.PointerToRawData) +
        Section.SizeOfRawData);
    end;
  end;

  Result := Min(MaxOffset, Stream.Size);
end;

end.
