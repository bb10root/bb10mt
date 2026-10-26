unit nvre;

interface

uses
  SysUtils, Classes, crc;

procedure ExtractNVRAMBlocks(Stream: TStream; const OutputDir: string);

implementation

type
  TNVRAMBlockHeader = packed record
    unk1: word;
    BlockNum: word;
    Revision: DWord;
    DataCrc: DWord;
    unk2: DWord;
    BlockLen: DWord;
    DataLen: DWord;
    HdrCrc: DWord;
  end;

  TNVRAMBlock = record
    Header: TNVRAMBlockHeader;
    Data: TBytes;
    Magic: DWord;
  end;

const
  HeaderSize = SizeOf(TNVRAMBlockHeader);
  NVRE_MAGIC = $4552564E; // 'NVRE'

function ReadOneNVRAMBlock(Stream: TStream; var Block: TNVRAMBlock): boolean;
begin
  Result := False;

  if Stream.Position + HeaderSize + 4 > Stream.Size then Exit;

  if Stream.Read(Block.Header, HeaderSize) <> HeaderSize then Exit;

  // Перевірка sanity check довжини, щоб уникнути виділення надмірної пам'яті
  if (Block.Header.DataLen > Stream.Size) or (Stream.Position +
    Block.Header.DataLen + 4 > Stream.Size) then Exit;

  SetLength(Block.Data, Block.Header.DataLen);
  if Block.Header.DataLen > 0 then
  begin
    if Stream.Read(Block.Data[0], Block.Header.DataLen) <>
      integer(Block.Header.DataLen) then Exit;
  end;

  if Stream.Read(Block.Magic, 4) <> 4 then Exit;

  Result := True;
end;

function IsValidNVRAMBlock(const Block: TNVRAMBlock): boolean;
var
  DataCRC, HdrCRC: DWord;
begin
  if DWord(Length(Block.Data)) <> Block.Header.DataLen then Exit(False);
  if Block.Magic <> NVRE_MAGIC then Exit(False);

  if Block.Header.DataLen > 0 then
  begin
    DataCRC := crc32(0, Pointer(Block.Data), Block.Header.DataLen);
    if DataCRC <> Block.Header.DataCrc then Exit(False);
  end;

  HdrCRC := crc32(0, @Block.Header, HeaderSize - SizeOf(DWord));
  if HdrCRC <> Block.Header.HdrCrc then Exit(False);

  Result := True;
end;

procedure ExtractNVRAMBlocks(Stream: TStream; const OutputDir: string);
var
  Block: TNVRAMBlock;
  Filename, Key, BasePath: string;
  FS: TFileStream;
  Index: integer;
  CountMap: TStringList;
  SavedPos, NextPos: int64;
  MapIndex: integer;
  Count: PtrInt;
begin
  ForceDirectories(OutputDir);
  BasePath := IncludeTrailingPathDelimiter(OutputDir);

  CountMap := TStringList.Create;
  try
    CountMap.Sorted := True;
    CountMap.Duplicates := dupAccept;
    // Дозволяємо додавання через бінарний пошук Find

    Index := 0;
    while Stream.Position < Stream.Size do
    begin
      SavedPos := Stream.Position;

      if not ReadOneNVRAMBlock(Stream, Block) then
      begin
        WriteLn(Format('Error reading block header at offset 0x%X', [SavedPos]));
        // Перехід на наступну межу 64KB (0x10000) без втрати бітів для великих файлів
        Stream.Position := (SavedPos + $FFFF) and not int64($FFFF);
        if Stream.Position <= SavedPos then
          Stream.Position := SavedPos + 1; // Запобігання зацикленню
        Continue;
      end;

      if not IsValidNVRAMBlock(Block) then
      begin
        // Якщо блок невалідний, вирівнюємося або зсуваємося вперед
        Stream.Position := (SavedPos + $FFFF) and not int64($FFFF);
        if Stream.Position <= SavedPos then
          Stream.Position := SavedPos + 1;
        Continue;
      end;

      Inc(Index);
      Key := Format('%.4X+%.8X', [Block.Header.BlockNum, Block.Header.Revision]);

      // Бінарний пошук O(log N) замість O(N)
      if CountMap.Find(Key, MapIndex) then
      begin
        Count := PtrInt(CountMap.Objects[MapIndex]) + 1;
        CountMap.Objects[MapIndex] := TObject(Count);
        Filename := Format('%s%s_%d.bin', [BasePath, Key, Count]);
      end
      else
      begin
        Count := 1;
        CountMap.AddObject(Key, TObject(Count));
        Filename := Format('%s%s.bin', [BasePath, Key]);
      end;

      // Запис блоку у файл
      FS := TFileStream.Create(Filename, fmCreate);
      try
        if Length(Block.Data) > 0 then
          FS.WriteBuffer(Block.Data[0], Length(Block.Data));
        WriteLn('Saved: ', Filename);
      finally
        FS.Free;
      end;

      // Перехід до наступного блоку згідно із заголовочним розміром BlockLen
      NextPos := SavedPos + Block.Header.BlockLen;
      if NextPos <= SavedPos then
        NextPos := SavedPos + HeaderSize + Block.Header.DataLen + 4;
      // Резервний зсув

      Stream.Position := NextPos;
    end;
  finally
    CountMap.Free;
  end;
end;

end.
