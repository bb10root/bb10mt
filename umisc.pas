unit uMisc;

{$mode objfpc}{$H+}

interface

uses
  SysUtils, Classes{$IFDEF USEGENERICS}, Generics.Collections{$ELSE}, lgQueue, lgHashSet{$ENDIF};

type
  TProgressCallback = procedure(fName: string; current, total: int64);


type
  {$IFDEF USEGENERICS}
  TQueueX = specialize TQueue<dword>;
  TSetX=  specialize TCustomSet<DWord>;
  {$ELSE}
  TQueueX = specialize TGLiteQueue<dword>;
  TSetSpec = specialize TGLiteHashSetLP<DWord, Dword>;
  TSetX = TSetSpec.TSet;
  {$ENDIF}

  TFreeBlocks = class
  private
    fQueue: TQueueX;
    fSet: TSetX;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Enqueue(Value: DWord);
    procedure Clear;
    function Dequeue: DWord;
    function TryDequeue(out val: DWord): boolean;
    function Contains(Value: DWord): boolean;
    function Count: integer;
  end;


function IsFullFFBlock(var Buf: TBytes; Size: integer): boolean;
function IsEmptyBlock(var Buf: TBytes; Size: integer): boolean;
function IsFullFFBlock_Branchless(var Buf: TBytes; Size: integer): boolean;

function TryStrToInt64AutoBase(const S: string; out Value: int64): boolean;
function TryStrToInt64BaseManual(const S: string; Base: integer; out Value: int64): boolean;
function TryCharToDigit(C: char; out D: integer): boolean;

function CRC32_QNX(const Data: pbyte; Len: integer): cardinal; overload;
function CRC32_QNX(const S: ansistring): cardinal; overload;

function CalcCRC32(const Buf; Len: longword): longword; inline;
function CRC32FromStream(Stream: TStream; StartPos, Count: int64): cardinal;

function Fletcher32_Checksum(const Data: pbyte; Len: integer): cardinal; overload;
function Fletcher32_Checksum(const S: ansistring): cardinal; overload;

procedure CopyStreamData(Source, Dest: TStream; Size: int64);

function GetExeDirectory: string;
function ReadCString(const arr: array of ansichar): string;

function qnx6_lfile_checksum(Name: Pointer; size: word): DWord;
function Iceil(q, r: DWord): DWord; inline;
function GetParentFolder(const AFolder: string): string;
function IsPowerOfTwo(const x: integer): boolean; inline;

procedure ReverseBytesInPlace(var A: TBytes);

function StrToHex(const S: string): string;
function BytesToHexString(const B: TBytes): string;
function HexStringToBytes(const S: string): TBytes;
function AsciiStringToBytes(const S: string): TBytes;

implementation

uses crc, Math;

function StrToHex(const S: string): string;
var
  i: integer;
begin
  Result := '';
  for i := 1 to Length(S) do
    Result := Result + IntToHex(Ord(S[i]), 2);
end;

const
  HexDigits: array[0..15] of char = '0123456789abcdef';


function BytesToHexString(const B: TBytes): string;
var
  i: integer;
begin
  SetLength(Result, Length(B) * 2);
  for i := 0 to Length(B) - 1 do
  begin
    Result[2 * i + 1] := HexDigits[B[i] shr 4];
    Result[2 * i + 2] := HexDigits[B[i] and $F];
  end;
end;

function HexCharToNibble(c: char): byte;
begin
  if (c >= '0') and (c <= '9') then
    Result := Ord(c) - Ord('0')
  else if (c >= 'a') and (c <= 'f') then
    Result := Ord(c) - Ord('a') + 10
  else if (c >= 'A') and (c <= 'F') then
    Result := Ord(c) - Ord('A') + 10
  else
    Result := 0;
end;


function HexStringToBytes(const S: string): TBytes;
var
  i, n: integer;
begin
  n := Length(S) div 2;
  SetLength(Result, n);
  for i := 0 to n - 1 do
    Result[i] :=
      (HexCharToNibble(S[2 * i + 1]) shl 4) or HexCharToNibble(S[2 * i + 2]);
end;

function AsciiStringToBytes(const S: string): TBytes;
var
  Len: integer;
begin
  Len := Length(S);
  SetLength(Result, Len);
  if Len > 0 then
    Move(S[1], Result[0], Len);
end;


{$PUSH}
{$optimization LEVEL4}// Вмикає векторизацію та розгортання циклів
{$Q-}// Вимикає перевірки діапазону
{$R-}// Вимикає перевірки цілочисельного переповнення

function IsEmptyBlock(var Buf: TBytes; Size: integer): boolean;
{$IFDEF CPUX86}
{$ASMMODE intel}
asm
  // EAX = Buf, EDX = Size
  push esi
  mov esi, eax
  mov ecx, edx
  shr ecx, 2
  jz @CheckRemaining

@CheckDWords:
  mov eax, [esi]
  test eax, eax
  jnz @NotEmpty
  add esi, 4
  dec ecx
  jnz @CheckDWords

@CheckRemaining:
  mov ecx, edx
  and ecx, 3
  jz @Empty

@CheckBytes:
  mov al, [esi]
  test al, al
  jnz @NotEmpty
  inc esi
  dec ecx
  jnz @CheckBytes

@Empty:
  mov eax, 1
  pop esi
  ret

@NotEmpty:
  xor eax, eax
  pop esi
end;
  {$ELSE}
var
  i: integer;
  p: PQWord;
begin
  Result := True;
  p := @Buf[0];

  for i := 0 to (Size div 8) - 1 do
  begin
    if p^ <> 0 then
      Exit(False);
    Inc(p);
  end;

  for i := 0 to (Size mod 8) - 1 do
  begin
    if pbyte(p)^ <> 0 then
      Exit(False);
    Inc(pbyte(p));
  end;
end;

// ---------------- Branchless базовий варіант ----------------
function IsFullFFBlock_Branchless(var Buf: TBytes; Size: integer): boolean;
var
  i: integer;
  p: PUInt64;
  mask: uint64;
begin
  if Size = 0 then Exit(False);
  p := @Buf[0];
  mask := 0;

  for i := 0 to (Size div 8) - 1 do
  begin
    mask := mask or (p^ xor QWord(-1));
    Inc(p);
  end;

  for i := 0 to (Size mod 8) - 1 do
  begin
    mask := mask or (pbyte(p)^ xor $FF);
    Inc(pbyte(p));
  end;

  Result := (mask = 0);
end;
{$ENDIF}
{$POP}


// ---------------- SSE2 (16 байт за раз) ----------------
{$IFDEF CPUX86_64}
{$ASMMODE intel}
function IsFullFFBlock_SSE2(var Buf: TBytes; Size: Integer): Boolean; assembler;
asm
  // Вхід: RDI = Buf, RSI = Size
  mov rsi, rsi       // Size
  test rsi, rsi
  jz @Full

  mov rdx, rdi       // Ptr = Buf

@Loop16:
  cmp rsi, 16
  jb @TailBytes
  movdqu xmm0, [rdx]         // завантажуємо 16 байт
  pxor xmm1, xmm1             // обнуляємо xmm1
  pcmpeqb xmm1, xmm1          // xmm1 = 0xFF...FF
  pxor xmm0, xmm1             // xmm0 = xmm0 XOR 0xFF
  pmovmskb eax, xmm0          // отримуємо маску
  test eax, eax
  jne @NotFull
  add rdx, 16
  sub rsi, 16
  jmp @Loop16

@TailBytes:
  test rsi, rsi
  jz @Full

@CheckByte:
  mov al, [rdx]
  cmp al, $FF
  jne @NotFull
  inc rdx
  dec rsi
  jnz @CheckByte

@Full:
  mov eax, 1
  ret

@NotFull:
  xor eax, eax
end;

{$ENDIF}

// ---------------- AVX2 (32 байти за раз) ----------------
function IsFullFFBlock_AVX2(var Buf: TBytes; Size: integer): boolean;
var
  p: pbyte;
  mask: uint32;
begin
  if Size = 0 then Exit(False);
  p := @Buf[0];

  {$IFDEF CPUX86_64}
  mask := 0;
  while Size >= 32 do
  begin
    mask := mask or (PCardinal(p)^ xor $FFFFFFFF); Inc(p,4);
    mask := mask or (PCardinal(p)^ xor $FFFFFFFF); Inc(p,4);
    mask := mask or (PCardinal(p)^ xor $FFFFFFFF); Inc(p,4);
    mask := mask or (PCardinal(p)^ xor $FFFFFFFF); Inc(p,4);
    mask := mask or (PCardinal(p)^ xor $FFFFFFFF); Inc(p,4);
    mask := mask or (PCardinal(p)^ xor $FFFFFFFF); Inc(p,4);
    mask := mask or (PCardinal(p)^ xor $FFFFFFFF); Inc(p,4);
    mask := mask or (PCardinal(p)^ xor $FFFFFFFF); Inc(p,4);
    Dec(Size, 32);
  end;

  while Size > 0 do
  begin
    mask := mask or (p^ xor $FF);
    Inc(p);
    Dec(Size);
  end;

  Result := mask = 0;
  {$ELSE}
  Result := IsFullFFBlock_Branchless(Buf, Size);
  {$ENDIF}
end;

// ---------------- Автовибір найшвидшого варіанту ----------------
function IsFullFFBlock(var Buf: TBytes; Size: integer): boolean;
begin
  {$IFDEF CPUX86_64}
  // Якщо процесор підтримує AVX2 - використовуємо AVX2
    {$IF Defined(CPUAVX2)}
      Result := IsFullFFBlock_AVX2(Buf, Size)
    {$ELSEIF Defined(CPUX86_HAS_SSE2)}
      Result := IsFullFFBlock_SSE2(Buf, Size)
    {$ELSE}
      Result := IsFullFFBlock_Branchless(Buf, Size);
    {$ENDIF}
  {$ELSE}
  Result := IsFullFFBlock_Branchless(Buf, Size);
  {$ENDIF}
end;


function TryCharToDigit(C: char; out D: integer): boolean;
begin
  case C of
    '0'..'9': D := Ord(C) - Ord('0');
    'A'..'F': D := Ord(C) - Ord('A') + 10;
    'a'..'f': D := Ord(C) - Ord('a') + 10;
    else
      D := -1;
  end;
  Result := D >= 0;
end;

function TryStrToInt64BaseManual(const S: string; Base: integer; out Value: int64): boolean;
var
  i, D: integer;
  Negative: boolean;
  Tmp: int64;
begin
  Value := 0;
  Result := False;

  if S = '' then Exit;

  i := 1;
  Negative := False;

  if S[1] = '-' then
  begin
    Negative := True;
    Inc(i);
  end
  else if S[1] = '+' then
    Inc(i);

  if i > Length(S) then Exit;

  Tmp := 0;
  for i := i to Length(S) do
  begin
    if not TryCharToDigit(S[i], D) or (D >= Base) then Exit;
    // Check for overflow
    if (Tmp > (High(int64) - D) div Base) then Exit;
    Tmp := Tmp * Base + D;
  end;

  if Negative then
    Value := -Tmp
  else
    Value := Tmp;

  Result := True;
end;

function TryStrToInt64AutoBase(const S: string; out Value: int64): boolean;
var
  Tmp: string;
  Base: integer;
begin
  Tmp := Trim(S);
  Value := 0;
  Result := False;

  if Tmp = '' then Exit;

  Base := 10;

  if Tmp[1] = '-' then
  begin
    if Length(Tmp) > 2 then
    begin
      if (Tmp[2] = '$') then
      begin
        Base := 16;
        Tmp := '-' + Copy(Tmp, 3, MaxInt);
      end
      else if (Tmp[2] = '0') and (Length(Tmp) > 3) then
      begin
        case Tmp[3] of
          'x', 'X': begin
            Base := 16;
            Tmp := '-' + Copy(Tmp, 4, MaxInt);
          end;
          'b', 'B': begin
            Base := 2;
            Tmp := '-' + Copy(Tmp, 4, MaxInt);
          end;
          'o', 'O': begin
            Base := 8;
            Tmp := '-' + Copy(Tmp, 4, MaxInt);
          end;
        end;
      end;
    end;
  end
  else
  begin
    if Tmp[1] = '$' then
    begin
      Base := 16;
      Tmp := Copy(Tmp, 2, MaxInt);
    end
    else if (Tmp[1] = '0') and (Length(Tmp) > 2) then
    begin
      case Tmp[2] of
        'x', 'X': begin
          Base := 16;
          Tmp := Copy(Tmp, 3, MaxInt);
        end;
        'b', 'B': begin
          Base := 2;
          Tmp := Copy(Tmp, 3, MaxInt);
        end;
        'o', 'O': begin
          Base := 8;
          Tmp := Copy(Tmp, 3, MaxInt);
        end;
      end;
    end;
  end;

  Result := TryStrToInt64BaseManual(Tmp, Base, Value);
end;

function CalcCRC32(const Buf; Len: longword): longword; inline;
begin
  Result := crc32(0, @Buf, Len);
end;


function CRC32FromStream(Stream: TStream; StartPos, Count: int64): cardinal;
const
  BufSize = 65536; // 64 KB
var
  Buffer: array[0..BufSize - 1] of byte;
  SavedPos: int64;
  ToRead, ReadBytes: longint;
  Left: int64;
begin
  SavedPos := Stream.Position;
  try
    if StartPos < 0 then
      StartPos := 0;
    if StartPos > Stream.Size then
      StartPos := Stream.Size;
    Stream.Position := StartPos;

    if Count < 0 then
      Left := Stream.Size - StartPos
    else
    begin
      if Count > (Stream.Size - StartPos) then
        Count := Stream.Size - StartPos;
      Left := Count;
    end;

    Result := crc32(0, nil, 0);

    while Left > 0 do
    begin
      if Left > BufSize then
        ToRead := BufSize
      else
        ToRead := Left;

      ReadBytes := Stream.Read(Buffer, ToRead);
      if ReadBytes <= 0 then
        Break;

      Result := crc32(Result, @Buffer[0], ReadBytes);
      Dec(Left, ReadBytes);
    end;
  finally
    try
      Stream.Position := SavedPos;
    except
    end;
  end;
end;

function ReadCString(const arr: array of ansichar): string;
var
  i: integer;
begin
  Result := '';
  for i := 0 to High(arr) do
  begin
    if arr[i] = #0 then Break;
    Result := Result + arr[i];
  end;
end;

{$IFDEF DARWIN}
{$linklib c}
function _NSGetExecutablePath(buf: PChar; bufsize: PLongWord): Integer; cdecl; external;
{$ENDIF}

function GetExeDirectory: string;
  {$IFDEF DARWIN}
var
  buf: array[0..1023] of Char;
  size: UInt32;
  {$ENDIF}
begin
  {$IFDEF DARWIN}
  size := Length(buf);
  if _NSGetExecutablePath(@buf, @size) = 0 then
    Result := IncludeTrailingPathDelimiter(ExtractFilePath(StrPas(buf)))
  else
    Result := IncludeTrailingPathDelimiter(ExtractFilePath(ParamStr(0)));
  {$ELSE}
  Result := IncludeTrailingPathDelimiter(ExtractFilePath(ParamStr(0)));
  {$ENDIF}
end;

const
  MAX_BUFFER_SIZE = 1024 * 1024;

procedure CopyStreamData(Source, Dest: TStream; Size: int64);
var
  Buffer: array of byte;
  Remaining, ChunkSize: int64;
  BufferSize: integer;
begin
  BufferSize := Min(MAX_BUFFER_SIZE, Size);
  SetLength(Buffer, BufferSize);
  Remaining := Size;

  while Remaining > 0 do
  begin
    ChunkSize := Min(Remaining, BufferSize);
    if Source.Read(Buffer[0], ChunkSize) <> ChunkSize then
      raise Exception.Create('Error reading source data');
    if Dest.Write(Buffer[0], ChunkSize) <> ChunkSize then
      raise Exception.Create('Error writing destination data');
    Dec(Remaining, ChunkSize);
  end;
end;

const
  POLY = $04C11DB7;

var
  CRCTable: array[0..255] of cardinal;

procedure InitCRCTable;
var
  i, j: integer;
  crc: cardinal;
begin
  for i := 0 to 255 do
  begin
    crc := cardinal(i) shl 24;
    for j := 0 to 7 do
    begin
      if (crc and $80000000) <> 0 then
        crc := (crc shl 1) xor POLY
      else
        crc := crc shl 1;
    end;
    CRCTable[i] := crc;
  end;
end;

function CRC32_QNX(const Data: pbyte; Len: integer): cardinal;
var
  i: integer;
  crc: cardinal;
begin
  crc := 0; // Init = 0
  for i := 0 to Len - 1 do
    crc := (crc shl 8) xor CRCTable[((crc shr 24) xor Data[i]) and $FF];
  Result := crc; // XorOut = 0
end;

function CRC32_QNX(const S: ansistring): cardinal;
begin
  Result := CRC32_QNX(@S[1], Length(S));
end;

function IsPowerOfTwo(const x: integer): boolean; inline;
begin
  Result := (x > 0) and ((x and (x - 1)) = 0);
end;

function GetParentFolder(const AFolder: string): string;
begin
  Result := ExtractFileDir(ExcludeTrailingPathDelimiter(AFolder));
  if Result = '' then
    Result := DirectorySeparator;
end;


function Iceil(q, r: DWord): DWord; inline;
begin
  if r = 0 then
    raise Exception.Create('Division by zero in Iceil');
  Result := (q + r - 1) div r;
end;

function qnx6_lfile_checksum(Name: Pointer; size: word): DWord;
var
  i: integer;
  p: pbyte;
  r: DWord;
begin
  p := Name;
  r := 0;
  for i := 0 to size - 1 do
    r := Dword(((r shr 1) or (r shl 31)) + p^); // одразу обертання + додавання
  Inc(p);
  Result := r;
end;


constructor TFreeBlocks.Create;
begin
  inherited Create;
  {$IFDEF USEGENERICS}
  fQueue := specialize TQueue<dword>.Create;
  fSet := specialize TCustomSet<DWord>.Create;
  {$ENDIF}
end;

destructor TFreeBlocks.Destroy;
begin
  {$IFDEF USEGENERICS}
  fQueue.Free;
  fSet.Free;
  {$ENDIF}
  inherited Destroy;
end;

procedure TFreeBlocks.Enqueue(Value: DWord);
begin
  if not fSet.Contains(Value) then
  begin
    fQueue.Enqueue(Value);
    fSet.Add(Value);
  end;
end;

procedure TFreeBlocks.Clear;
begin
  fQueue.Clear;
  fSet.Clear;
end;

function TFreeBlocks.TryDequeue(out val: DWord): boolean;
begin
  {$IFDEF USEGENERICS}
  if fQueue.Count > 0 then
  begin
    val := fQueue.Dequeue;
    fSet.Remove(val);
    Result := true;
  end else
    Result := false;
  {$ELSE}
  Result := fQueue.TryDequeue(val);
  if Result then
    fSet.Remove(val);
  {$ENDIF}
end;

function TFreeBlocks.Dequeue: DWord;
begin
  if fQueue.Count > 0 then
  begin
    Result := fQueue.Dequeue;
    fSet.Remove(Result);
  end
  else
    Result := 0; // or raise exception
end;

function TFreeBlocks.Contains(Value: DWord): boolean;
begin
  Result := fSet.Contains(Value);
end;

function TFreeBlocks.Count: integer;
begin
  Result := fQueue.Count;
end;

function Fletcher32_Checksum(const Data: pbyte; Len: integer): cardinal;
var
  sum1, sum2: cardinal;
  i: integer;
  wordVal: word;
begin
  sum1 := 0;
  sum2 := 0;

  i := 0;
  while i < Len do
  begin
    if i + 1 < Len then
      wordVal := (Data[i] shl 8) or Data[i + 1]
    else
      wordVal := Data[i] shl 8; // останній байт без пари
    Inc(i, 2);

    sum1 := (sum1 + wordVal) mod 65535;
    sum2 := (sum2 + sum1) mod 65535;
  end;

  Result := (sum2 shl 16) or sum1;
end;

function Fletcher32_Checksum(const S: ansistring): cardinal;
begin
  Result := Fletcher32_Checksum(@S[1], Length(S));
end;

procedure ReverseBytesInPlace(var A: TBytes);
var
  i, j: integer;
  tmp: byte;
begin
  i := 0;
  j := High(A);
  while i < j do
  begin
    tmp := A[i];
    A[i] := A[j];
    A[j] := tmp;
    Inc(i);
    Dec(j);
  end;
end;

initialization
  InitCRCTable;

end.
