unit RIMSignatureParser;

{$mode objfpc}{$H+}{$PACKRECORDS C}

interface

uses
  SysUtils, Classes;

type
  PSectionHeaderFooter = ^TSectionHeaderFooter;

  TSectionHeaderFooter = packed record
    TotalLength: longword;
    Version: word;
    SubFlags: word;
    Magic: longword;
  end;

  PSectionHeader = ^TSectionHeader;

  TSectionHeader = packed record
    NameBuf: array[0..31] of char;
    ShortIDBuf: array[0..3] of char;
    PayloadLength: longword;
  end;

  TQNXSection = record
    NameHeader: string;
    ShortID: string;
    PayloadLength: longword;
    Payload: array of byte;
    TotalSectionLength: longword;
    Version: word;
    SubFlags: word;
    MagicNumber: longword;
    Offset: int64;
  end;

  TQNXSectionArray = array of TQNXSection;

// 1. Швидке визначення розміру блоку
function GetSignatureBlockSize(const Buffer: array of byte): int64; overload;
function GetSignatureBlockSize(Stream: TStream): int64; overload;

// 2. Повний розбір у масив секцій
function GetSignatureSections(const Buffer: array of byte): TQNXSectionArray; overload;
function GetSignatureSections(Stream: TStream): TQNXSectionArray; overload;

implementation

const
  MAGIC_HIGH = $B5A60BFD; // Little-Endian (FD 0B A6 B5)
  MAGIC_LOW = $C6B71C0E; // Little-Endian (0E 1C B7 C6)
  MAGIC_BASE = $D7C82D1F; // Little-Endian (1F 2D C8 D7)

  MIN_SECTION_SIZE = SizeOf(TSectionHeader) + SizeOf(TSectionHeaderFooter); // 40 + 12 = 52

{$INLINE ON}
function IsValidMagic(const Magic: longword): boolean; inline;
begin
  Result := (Magic = MAGIC_HIGH) or (Magic = MAGIC_LOW) or (Magic = MAGIC_BASE);
end;

// ============================================================================
// Базова низькорівнева реалізація через вказівники
// ============================================================================

function GetSignatureBlockSizePtr(PBuf: pbyte; const BufLen: int64): int64;
var
  CurrEndPos: int64;
  SecFooter: PSectionHeaderFooter;
begin
  Result := 0;
  if BufLen < (SizeOf(TSectionHeaderFooter) + 4) then
    Exit;

  CurrEndPos := BufLen - 4; // Пропускаємо маркер/CRC32 контейнера

  while CurrEndPos >= SizeOf(TSectionHeaderFooter) do
  begin
    SecFooter := PSectionHeaderFooter(PBuf + CurrEndPos - SizeOf(TSectionHeaderFooter));

    if not IsValidMagic(SecFooter^.Magic) or (SecFooter^.TotalLength < MIN_SECTION_SIZE) or
      (CurrEndPos < SecFooter^.TotalLength) then
      Break;

    CurrEndPos := CurrEndPos - SecFooter^.TotalLength;
  end;

  if CurrEndPos < (BufLen - 4) then
    Result := BufLen - CurrEndPos;
end;

function GetSignatureSectionsPtr(PBuf: pbyte; const BufLen: int64; BaseOffset: int64 = 0): TQNXSectionArray;
var
  CurrEndPos: int64;
  SecFooter: PSectionHeaderFooter;
  SecHeader: PSectionHeader;
  Count, Capacity: integer;
  SecOffset: int64;
begin
  SetLength(Result, 0);
  if BufLen < (SizeOf(TSectionHeaderFooter) + 4) then
    Exit;

  CurrEndPos := BufLen - 4;
  Count := 0;
  Capacity := 8; // Початковий резерв, щоб уникнути частих realloc
  SetLength(Result, Capacity);

  while CurrEndPos >= SizeOf(TSectionHeaderFooter) do
  begin
    SecFooter := PSectionHeaderFooter(PBuf + CurrEndPos - SizeOf(TSectionHeaderFooter));

    if not IsValidMagic(SecFooter^.Magic) or (SecFooter^.TotalLength < MIN_SECTION_SIZE) or
      (CurrEndPos < SecFooter^.TotalLength) then
      Break;

    SecOffset := CurrEndPos - SecFooter^.TotalLength;
    SecHeader := PSectionHeader(PBuf + SecOffset);

    // Розширюємо масив при потребі
    if Count >= Capacity then
    begin
      Capacity := Capacity * 2;
      SetLength(Result, Capacity);
    end;

    with Result[Count] do
    begin
      TotalSectionLength := SecFooter^.TotalLength;
      Version := SecFooter^.Version;
      SubFlags := SecFooter^.SubFlags;
      MagicNumber := SecFooter^.Magic;
      Offset := BaseOffset + SecOffset;

      PayloadLength := SecHeader^.PayloadLength;

      SetString(NameHeader, PChar(@SecHeader^.NameBuf[0]), 32);
      NameHeader := Trim(NameHeader);

      SetString(ShortID, PChar(@SecHeader^.ShortIDBuf[0]), 4);
      ShortID := Trim(ShortID);

      SetLength(Payload, PayloadLength);
      if PayloadLength > 0 then
        Move((PBuf + SecOffset + SizeOf(TSectionHeader))^, Payload[0], PayloadLength);
    end;

    Inc(Count);
    CurrEndPos := SecOffset;
  end;

  SetLength(Result, Count); // Обрізаємо залишкову ємність
end;

// ============================================================================
// Публічні overloaded-функції для array of Byte
// ============================================================================

function GetSignatureBlockSize(const Buffer: array of byte): int64;
begin
  if Length(Buffer) = 0 then Exit(0);
  Result := GetSignatureBlockSizePtr(@Buffer[0], Length(Buffer));
end;

function GetSignatureSections(const Buffer: array of byte): TQNXSectionArray;
begin
  if Length(Buffer) = 0 then Exit(nil);
  Result := GetSignatureSectionsPtr(@Buffer[0], Length(Buffer));
end;

// ============================================================================
// Публічні overloaded-функції для TStream
// ============================================================================

function GetSignatureBlockSize(Stream: TStream): int64;
var
  TailSize, StreamSize: int64;
  RawBuf: array of byte;
  OldPos: int64;
begin
  Result := 0;
  if not Assigned(Stream) then Exit;

  StreamSize := Stream.Size;
  if StreamSize < (SizeOf(TSectionHeaderFooter) + 4) then Exit;

  // Для швидкого вимірювання беремо лише останній кавал файлу (наприклад, 4KB)
  TailSize := 4096;
  if TailSize > StreamSize then
    TailSize := StreamSize;

  SetLength(RawBuf, TailSize);
  OldPos := Stream.Position;
  try
    Stream.Position := StreamSize - TailSize;
    Stream.ReadBuffer(RawBuf[0], TailSize);

    Result := GetSignatureBlockSizePtr(@RawBuf[0], TailSize);
  finally
    Stream.Position := OldPos;
  end;
end;

function GetSignatureSections(Stream: TStream): TQNXSectionArray;
var
  BlockSize, StreamSize, OldPos: int64;
  RawBuf: array of byte;
begin
  SetLength(Result, 0);
  if not Assigned(Stream) then Exit;

  StreamSize := Stream.Size;
  BlockSize := GetSignatureBlockSize(Stream);
  if BlockSize = 0 then Exit;

  SetLength(RawBuf, BlockSize);
  OldPos := Stream.Position;
  try
    Stream.Position := StreamSize - BlockSize;
    Stream.ReadBuffer(RawBuf[0], BlockSize);

    Result := GetSignatureSectionsPtr(@RawBuf[0], BlockSize, StreamSize - BlockSize);
  finally
    Stream.Position := OldPos;
  end;
end;

end.
