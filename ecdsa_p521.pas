unit ecdsa_p521;

{$mode objfpc}{$H+}
{$modeswitch advancedrecords}
interface

uses
  Classes, SysUtils;

type
  // Abstract big-int handle (adapter uses internal implementation)
  TBIHandle = Pointer;

  // Point on curve
  TECPoint = record
    X, Y: TBIHandle;
    Infinity: boolean;
  public
    function Create(const aX, aY: TBIHandle; const aInfinity: boolean): TECPoint;
  end;

  // Signature pair
  TECDSASignature = record
    R, S: TBIHandle;
  end;


  { Public API }

procedure ECDSA_GenerateKey(out Priv: TBIHandle; out Pub: TECPoint);
// buffer msg: pointer to message bytes, len: length in bytes
procedure ECDSA_Sign(const Msg: Pointer; const MsgLen: nativeint; const Priv: TBIHandle;
  out Sig: TECDSASignature);
function ECDSA_Verify(const Msg: Pointer; const MsgLen: nativeint; const Pub: TECPoint;
  const Sig: TECDSASignature): boolean;

// Helpers for encoding/decoding DER/point
function EncodePointUncompressed(const P: TECPoint): TBytes;
function DecodePointUncompressed(const Buf: TBytes; out P: TECPoint): boolean;

function HMAC_SHA1(const Key, Data: TBytes): TBytes;
function HMAC_SHA224(const Key, Data: TBytes): TBytes;
function HMAC_SHA256(const Key, Data: TBytes): TBytes;
function HMAC_SHA384(const Key, Data: TBytes): TBytes;
function HMAC_SHA512(const Key, Data: TBytes): TBytes;

implementation

uses mormot.crypt.core, mormot.crypt.rsa, mormot.core.base, Math;

type
  PEC_Curve = ^TEC_Curve;

  TEC_Curve = record
    P: PBigInt; // модуль
    A: PBigInt; // коефіцієнт a
    B: PBigInt; // коефіцієнт b
  end;

var
  GlobalRsaContext: TRsaContext;

function TECPoint.Create(const aX, aY: TBIHandle; const aInfinity: boolean): TECPoint;
begin
  Result.X := aX;
  Result.Y := aY;
  Result.Infinity := aInfinity;
end;

{
  ----------------------------
  === BIGINT ADAPTER LAYER ===
  ----------------------------
}

const
  // Перетворення nibble → hex
  NibbleToHex: array[0..15] of char =
    ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F');

  // Перетворення hex char → nibble
  HexCharToNibble: array[char] of byte = (
    // '0'-'9', 'A'-'F', 'a'-'f', решта $FF
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, //0..15
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, //16..31
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, //32..47
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, $FF, $FF, $FF, $FF, $FF, $FF, // '0'-'9' = 48..57
    $FF, $FF, $FF, $FF, $FF, $FF, // 58..63
    $FF, $10, $11, $12, $13, $14, $15, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, // 'A'-'F' = 65..70
    $FF, $10, $11, $12, $13, $14, $15, // 'a'-'f' = 97..102
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
    $FF, $FF, $FF
    );


{ --------------------------
  FromBytes: little-endian
-------------------------- }
function BI_FromBytes_LE(const Buf: TBytes; TrimLeadingZeros: boolean = True): PBigInt;
var
  nWords, i, idx: integer;
  w: HalfUInt;
begin
  nWords := (Length(Buf) + 3) div 4;
  if nWords = 0 then nWords := 1;

  Result := GlobalRsaContext.Allocate(nWords, []);
  FillChar(Result^.Value^, nWords * SizeOf(HalfUInt), 0);

  idx := 0;
  for i := 0 to nWords - 1 do
  begin
    w := 0;
    if idx < Length(Buf) then w := Buf[idx];
    if idx + 1 < Length(Buf) then w := w or (Buf[idx + 1] shl 8);
    if idx + 2 < Length(Buf) then w := w or (Buf[idx + 2] shl 16);
    if idx + 3 < Length(Buf) then w := w or (Buf[idx + 3] shl 24);
    Result^.Value^[i] := w;
    Inc(idx, 4);
  end;

  if TrimLeadingZeros then
    while (Result^.Size > 1) and (Result^.Value^[Result^.Size - 1] = 0) do Dec(Result^.Size);
end;


{ --------------------------
  ToBytes: little-endian
-------------------------- }
function BI_ToBytes_LE(H: PBigInt; TrimLeadingZeros: boolean = True): TBytes;
var
  i, idx, bLen: integer;
  w: HalfUInt;
begin
  bLen := H^.Size * 4;
  SetLength(Result, bLen);

  idx := 0;
  for i := 0 to H^.Size - 1 do
  begin
    w := H^.Value^[i];
    Result[idx] := w and $FF;
    Result[idx + 1] := (w shr 8) and $FF;
    Result[idx + 2] := (w shr 16) and $FF;
    Result[idx + 3] := (w shr 24) and $FF;
    Inc(idx, 4);
  end;

  if TrimLeadingZeros then
  begin
    i := Length(Result) - 1;
    while (i > 0) and (Result[i] = 0) do Dec(i);
    SetLength(Result, i + 1);
  end;
end;

{ --------------------------
  FromHex: little-endian
-------------------------- }
function BI_FromHex_LE(const HexStr: string; TrimLeadingZeros: boolean = True): PBigInt;
var
  i, j, nWords, hexLen: integer;
  val: HalfUInt;
begin
  hexLen := Length(HexStr);
  nWords := (hexLen + 7) div 8;
  if nWords = 0 then nWords := 1;

  Result := GlobalRsaContext.Allocate(nWords, []);
  FillChar(Result^.Value^, nWords * SizeOf(HalfUInt), 0);

  i := hexLen;
  nWords := 0;
  while i > 0 do
  begin
    val := 0;
    for j := 0 to 7 do
    begin
      if i - j < 1 then Break;
      val := val or (HexCharToNibble[HexStr[i - j]] shl (j * 4));
    end;
    Result^.Value^[nWords] := val;
    Inc(nWords);
    Dec(i, 8);
  end;

  if TrimLeadingZeros then
    while (Result^.Size > 1) and (Result^.Value^[Result^.Size - 1] = 0) do Dec(Result^.Size);
end;

{ --------------------------
  ToHex: little-endian
-------------------------- }
function BI_ToHex_LE(H: PBigInt; TrimLeadingZeros: boolean = True): string;
var
  i, j: integer;
  b: HalfUInt;
  nib: byte;
  leading: boolean;
begin
  Result := '';
  leading := True;

  for i := H^.Size - 1 downto 0 do
  begin
    b := H^.Value^[i];
    for j := 7 downto 0 do
    begin
      nib := (b shr (j * 4)) and $F;
      if (nib <> 0) or (not leading) or ((i = 0) and (j = 0)) then
      begin
        Result := Result + NibbleToHex[nib];
        leading := False;
      end;
    end;
  end;

  if TrimLeadingZeros and (Result = '') then Result := '0';
end;

function BI_FromBytes_BE(const Buf: TBytes; TrimLeadingZeros: boolean = True): PBigInt;
var
  nWords, i, idx: integer;
  w: HalfUInt;
begin
  nWords := (Length(Buf) + 3) div 4;
  if nWords = 0 then nWords := 1;

  Result := GlobalRsaContext.Allocate(nWords, []);
  FillChar(Result^.Value^, nWords * SizeOf(HalfUInt), 0);

  idx := 0;
  for i := nWords - 1 downto 0 do
  begin
    w := 0;
    if idx < Length(Buf) then w := Buf[idx] shl 24;
    if idx + 1 < Length(Buf) then w := w or (Buf[idx + 1] shl 16);
    if idx + 2 < Length(Buf) then w := w or (Buf[idx + 2] shl 8);
    if idx + 3 < Length(Buf) then w := w or Buf[idx + 3];
    Result^.Value^[i] := w;
    Inc(idx, 4);
  end;

  if TrimLeadingZeros then
    while (Result^.Size > 1) and (Result^.Value^[Result^.Size - 1] = 0) do Dec(Result^.Size);
end;

function BI_FromBytes_BE_Ptr(const Buf: pbyte; Len: integer; TrimLeadingZeros: boolean = True): PBigInt;
var
  tmp: TBytes;
begin
  SetLength(tmp, Len);
  Move(Buf^, tmp[0], Len);
  Result := BI_FromBytes_BE(tmp, TrimLeadingZeros);
end;

function BI_ToBytes_BE(H: PBigInt; TrimLeadingZeros: boolean = True): TBytes;
var
  i, idx, bLen: integer;
  w: HalfUInt;
begin
  bLen := H^.Size * 4;
  SetLength(Result, bLen);

  idx := 0;
  for i := H^.Size - 1 downto 0 do
  begin
    w := H^.Value^[i];
    Result[idx] := (w shr 24) and $FF;
    Result[idx + 1] := (w shr 16) and $FF;
    Result[idx + 2] := (w shr 8) and $FF;
    Result[idx + 3] := w and $FF;
    Inc(idx, 4);
  end;

  if TrimLeadingZeros then
  begin
    i := 0;
    while (i < Length(Result) - 1) and (Result[i] = 0) do Inc(i);
    Result := Copy(Result, i, Length(Result) - i);
  end;
end;

function BI_FromHex_BE(const HexStr: string; TrimLeadingZeros: boolean = True): PBigInt;
var
  i, j, nWords, hexLen: integer;
  val: HalfUInt;
begin
  hexLen := Length(HexStr);
  nWords := (hexLen + 7) div 8;
  if nWords = 0 then nWords := 1;

  Result := GlobalRsaContext.Allocate(nWords, []);
  FillChar(Result^.Value^, nWords * SizeOf(HalfUInt), 0);

  nWords := 0;
  i := 1;
  while i <= hexLen do
  begin
    val := 0;
    for j := 0 to 7 do
    begin
      if i + j > hexLen then Break;
      val := (val shl 4) or HexCharToNibble[HexStr[i + j - 1]];
    end;
    Result^.Value^[nWords] := val;
    Inc(nWords);
    Inc(i, 8);
  end;

  if TrimLeadingZeros then
    while (Result^.Size > 1) and (Result^.Value^[Result^.Size - 1] = 0) do Dec(Result^.Size);
end;

function BI_ToHex_BE(H: PBigInt; TrimLeadingZeros: boolean = True): string;
var
  i, j: integer;
  b: HalfUInt;
  nib: byte;
  leading: boolean;
begin
  Result := '';
  leading := True;

  for i := H^.Size - 1 downto 0 do
  begin
    b := H^.Value^[i];
    for j := 7 downto 0 do
    begin
      nib := (b shr (j * 4)) and $F;
      if (nib <> 0) or (not leading) or ((i = 0) and (j = 0)) then
      begin
        Result := Result + NibbleToHex[nib];
        leading := False;
      end;
    end;
  end;

  if TrimLeadingZeros and (Result = '') then Result := '0';
end;

procedure BI_Free(H: TBIHandle); inline;
begin
  PBigInt(H)^.ResetPermanentAndRelease;
end;


function BI_ByteLength(H: PBigInt): integer;
var
  top: HalfUInt;
begin
  if H = nil then Exit(0);
  // визначаємо найвищий значущий байт в останньому слові
  top := H^.Value^[H^.Size - 1];
  Result := (H^.Size - 1) * 4; // попередні слова = 4 байти кожне
  // додаємо кількість байтів у верхньому слові
  if top > $FFFFFF then Result := Result + 4
  else if top > $FFFF then Result := Result + 3
  else if top > $FF then Result := Result + 2
  else if top > 0 then Result := Result + 1
  else
    Result := Result + 0;
end;

procedure BI_ToBytes_BE_Buffer(H: PBigInt; Dest: pbyte);
var
  i, j: integer;
  b: HalfUInt;
begin
  for i := 0 to H^.Size - 1 do
  begin
    b := H^.Value^[i];
    for j := 0 to 3 do
      Dest[(H^.Size - 1 - i) * 4 + j] := (b shr ((3 - j) * 8)) and $FF;
  end;
end;


function BI_One: TBIHandle;
begin
  Result := GlobalRsaContext.Allocate(1, []);
  PBigInt(Result)^.Value^[0] := 1;
end;

function BI_Zero: TBIHandle;
begin
  Result := GlobalRsaContext.Allocate(1, []);
  PBigInt(Result)^.Value^[0] := 0;
end;

function BI_IsEven(H: PBigInt): boolean;
begin
  if (H = nil) or (H^.Size = 0) then
    Exit(True); // нуль вважаємо парним
  Result := (H^.Value^[0] and 1) = 0;
end;

function BI_FromUInt32(AValue: uint32): TBIHandle;
begin
  Result := GlobalRsaContext.Allocate(1, []);
  PBigInt(Result)^.Value^[0] := AValue;
end;

function BI_Add(A, B: TBIHandle): TBIHandle;
begin
  Result := PBigInt(A)^.Add(B);
end;

function BI_Mod(A, B: TBIHandle): TBIHandle;
begin
  Result := PBigInt(A)^.Modulo(B);
end;

function BI_ModUInt32(H: PBigInt; N: cardinal): cardinal;
var
  i: integer;
  r: cardinal;
begin
  r := 0;
  for i := H^.Size - 1 downto 0 do
    r := ((r shl 32) + H^.Value^[i]) mod N;
  Result := r;
end;

function BI_AddUInt32(H: PBigInt; N: cardinal): PBigInt;
var
  Res: PBigInt;
  carry: uint64;
  i: integer;
begin
  New(Res);
  Res^.Size := H^.Size;
  GetMem(Res^.Value, Res^.Size * SizeOf(HalfUInt));
  Move(H^.Value^, Res^.Value^, H^.Size * SizeOf(HalfUInt));

  carry := N;
  for i := 0 to Res^.Size - 1 do
  begin
    carry := carry + Res^.Value^[i];
    Res^.Value^[i] := HalfUInt(carry and $FFFFFFFF);
    carry := carry shr 32;
    if carry = 0 then Break;
  end;

  if carry <> 0 then
  begin
    // додаємо новий найвищий елемент
    Inc(Res^.Size);
    ReallocMem(Res^.Value, Res^.Size * SizeOf(HalfUInt));
    Res^.Value^[Res^.Size - 1] := HalfUInt(carry);
  end;

  Result := Res;
end;

function BI_ModPow(b, exp, m: PBigInt): PBigInt;
begin
  Result := GlobalRsaContext.ModPower(b, exp, m);
end;

function BI_DivUInt32(H: PBigInt; N: cardinal): PBigInt;
var
  Res: PBigInt;
  i: integer;
  r: uint64;
begin
  if N = 0 then
    raise Exception.Create('Division by zero');

  New(Res);
  Res^.Size := H^.Size;
  GetMem(Res^.Value, Res^.Size * SizeOf(HalfUInt));

  r := 0;
  for i := H^.Size - 1 downto 0 do
  begin
    r := (r shl 32) or H^.Value^[i];
    Res^.Value^[i] := HalfUInt(r div N);
    r := r mod N;
  end;

  // видаляємо провідні нулі
  while (Res^.Size > 1) and (Res^.Value^[Res^.Size - 1] = 0) do
    Dec(Res^.Size);

  ReallocMem(Res^.Value, Res^.Size * SizeOf(HalfUInt));

  Result := Res;
end;

function BI_ModSqrt(X, P: PBigInt): PBigInt;
var
  exp: PBigInt;
begin
  // Перевірка: p ≡ 3 mod 4
  if (BI_ModUInt32(P, 4) <> 3) then
    raise Exception.Create('BI_ModSqrt: modulus P must be 3 mod 4');

  // exp = (P + 1) div 4
  exp := BI_AddUInt32(P, 1);
  BI_DivUInt32(exp, 4); // exp := (P+1)/4

  // y = X ^ exp mod P
  Result := BI_ModPow(X, exp, P);

  BI_Free(exp);
end;


function BI_Sub(A, B: TBIHandle): TBIHandle;
begin
  Result := PBigInt(A)^.Substract(B);
end;

function BI_AddMod(A, B, Modulus: TBIHandle): TBIHandle;
begin
  Result := PBigInt(A)^.Add(B)^.Modulo(Modulus);
end;

function BI_SubMod(A, B, Modulus: TBIHandle): TBIHandle;
begin
  Result := PBigInt(A)^.Substract(B)^.Modulo(Modulus);
end;

function BI_MulMod(A, B, Modulus: TBIHandle): TBIHandle;
begin
  Result := PBigInt(A)^.Multiply(B)^.Modulo(Modulus);

end;

function BI_InvMod(A, Modulus: TBIHandle): TBIHandle;
begin
  Result := PBigInt(A)^.ModInverse(Modulus);
end;

function BI_Compare(A, B: TBIHandle): integer;
begin
  Result := PBigInt(A)^.Compare(B);
end;

function BI_Copy(A: TBIHandle): TBIHandle;
begin
  Result := PBigInt(A)^.Copy;
end;

function BI_RandRange(MaxExclusive: TBIHandle): TBIHandle;
begin

end;

{ ----------------------------
  === Curve parameters P-521 ===
  Values taken from SEC2 / FIPS 186-4
  p, a, b, Gx, Gy, n, h
---------------------------- }

const
  // hex strings (SEC2)
  HEX_p =
    '01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF';
  HEX_a =
    '01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC';
  HEX_b =
    '0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00';
  HEX_Gx =
    '00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DFF2A3A6E4B7A2F1A8AAE9F3A9E4B1C8A16E7B3F2DE4D5A9E4BF8F9E3F3B2A3';
  HEX_Gy =
    '011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650';
  HEX_n =
    '01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409';
  HEX_h = '01';

var
  BI_p, BI_a, BI_b, BI_Gx, BI_Gy, BI_n, BI_h: TBIHandle;

{ ----------------------------
  === SMALL HASH / HMAC ===
  ----------------------------
  Below a minimal HMAC-SHA512 implementation is given that expects
  an external SHA512 function: SHA512(msg) -> 64-byte digest.
  If you have one, adapt HMAC_SHA512 to call it.
}

function SHA1_Short(const Msg: TBytes): TBytes;
var
  xSHA1: TSha1;
  digest: TSha1Digest;
begin
  xSHA1.Full(@Msg[0], Length(Msg), digest);
  SetLength(Result, Sizeof(TSha1Digest));
  move(digest[0], Result, Sizeof(TSha1Digest));
end;


function SHA224_Short(const Msg: TBytes): TBytes;
var
  xSHA224: TSha256;
  digest: TSha224Digest;
begin
  xSHA224.Full224(@Msg[0], Length(Msg), digest);
  SetLength(Result, Sizeof(TSha224Digest));
  move(digest[0], Result, Sizeof(TSha224Digest));
end;

function SHA256_Short(const Msg: TBytes): TBytes;
var
  xSHA256: TSha256;
  digest: TSha256Digest;
begin
  xSHA256.Full(@Msg[0], Length(Msg), digest);
  SetLength(Result, Sizeof(TSha256Digest));
  move(digest[0], Result, Sizeof(TSha256Digest));
end;

function SHA384_Short(const Msg: TBytes): TBytes;
var
  xSHA384: TSha384;
  digest: TSha384Digest;
begin
  xSHA384.Full(@Msg[0], Length(Msg), digest);
  SetLength(Result, Sizeof(TSha384Digest));
  move(digest[0], Result, Sizeof(TSha384Digest));
end;

function SHA512_Short(const Msg: TBytes): TBytes;
var
  xSHA512: TSha512;
  digest: TSha512Digest;
begin
  xSHA512.Full(@Msg[0], Length(Msg), digest);
  SetLength(Result, Sizeof(TSha512Digest));
  move(digest[0], Result, Sizeof(TSha512Digest));
end;

type
  THashFunction = function(const Data: TBytes): TBytes;

function HMAC(const Key, Data: TBytes; HashFunc: THashFunction; BlockSize: integer): TBytes;
var
  i: integer;
  k0, ipad, opad, innerData, outerData, Si: TBytes;
begin
  // Підготовка ключа
  SetLength(k0, BlockSize);
  FillChar(k0[0], BlockSize, 0);

  if Length(Key) > BlockSize then
    k0 := HashFunc(Key)
  else if Length(Key) > 0 then
    Move(Key[0], k0[0], Length(Key));

  // Створення ipad та opad
  SetLength(ipad, BlockSize);
  SetLength(opad, BlockSize);
  for i := 0 to BlockSize - 1 do
  begin
    ipad[i] := k0[i] xor $36;
    opad[i] := k0[i] xor $5c;
  end;

  // inner = Hash(ipad || Data)
  SetLength(innerData, BlockSize + Length(Data));
  Move(ipad[0], innerData[0], BlockSize);
  if Length(Data) > 0 then
    Move(Data[0], innerData[BlockSize], Length(Data));
  Si := HashFunc(innerData);

  // outer = Hash(opad || Si)
  SetLength(outerData, BlockSize + Length(Si));
  Move(opad[0], outerData[0], BlockSize);
  Move(Si[0], outerData[BlockSize], Length(Si));
  Result := HashFunc(outerData);
end;


function HMAC_SHA1(const Key, Data: TBytes): TBytes;
begin
  Result := HMAC(Key, Data, @SHA1_Short, SizeOf(TSha1Digest));
end;

function HMAC_SHA224(const Key, Data: TBytes): TBytes;
begin
  Result := HMAC(Key, Data, @SHA224_Short, SizeOf(TSha224Digest));
end;

function HMAC_SHA256(const Key, Data: TBytes): TBytes;
begin
  Result := HMAC(Key, Data, @SHA256_Short, SizeOf(TSha256Digest));
end;

function HMAC_SHA384(const Key, Data: TBytes): TBytes;
begin
  Result := HMAC(Key, Data, @SHA384_Short, SizeOf(TSha384Digest));
end;

function HMAC_SHA512(const Key, Data: TBytes): TBytes;
begin
  Result := HMAC(Key, Data, @SHA512_Short, SizeOf(TSha512Digest));
end;

{ ----------------------------
  === RFC6979 (HMAC-DRBG) for deterministic k
  uses HMAC-SHA512
---------------------------- }

function Bytes_Concat(const A, B: TBytes): TBytes;
begin
  SetLength(Result, Length(A) + Length(B));
  if Length(A) > 0 then Move(A[0], Result[0], Length(A));
  if Length(B) > 0 then Move(B[0], Result[Length(A)], Length(B));
end;

function Bytes_Concat3(const A, B, C: TBytes): TBytes;
begin
  SetLength(Result, Length(A) + Length(B) + Length(C));
  if Length(A) > 0 then Move(A[0], Result[0], Length(A));
  if Length(B) > 0 then Move(B[0], Result[Length(A)], Length(B));
  if Length(C) > 0 then Move(C[0], Result[Length(A) + Length(B)], Length(C));
end;

function RFC6979_GenerateK(const PrivBytes: TBytes; const Hash: TBytes; const q: TBIHandle): TBIHandle;
var
  V, K, bx, t, tmp: TBytes;
  qlenBytes, Tlen: integer;
  bi_tmp, kCandidate, qMinus1: TBIHandle;
begin
  // --- Step 1: initialize V and K ---
  SetLength(V, 64);  // 64 bytes for SHA-512
  FillChar(V[0], Length(V), $01);
  SetLength(K, 64);
  FillChar(K[0], Length(K), $00);

  // bx = priv || hash
  bx := Bytes_Concat(PrivBytes, Hash);

  // --- Step 2: K = HMAC(K, V || 0x00 || bx), V = HMAC(K, V) ---
  tmp := Bytes_Concat3(V, [$00], bx);
  K := HMAC_SHA512(K, tmp);
  V := HMAC_SHA512(K, V);

  // --- Step 3: K = HMAC(K, V || 0x01 || bx), V = HMAC(K, V) ---
  tmp := Bytes_Concat3(V, [$01], bx);
  K := HMAC_SHA512(K, tmp);
  V := HMAC_SHA512(K, V);

  // --- Step 4: generate candidate k ---
  qlenBytes := Length(BI_ToBytes_BE(q));
  Tlen := qlenBytes;

  qMinus1 := BI_Sub(q, BI_One); // q-1

  repeat
    // produce Tlen bytes from HMAC_DRBG
    SetLength(t, 0);
    while Length(t) < Tlen do
    begin
      V := HMAC_SHA512(K, V);
      t := Bytes_Concat(t, V);
    end;

    // truncate to qlenBytes
    SetLength(t, Tlen);

    // convert to integer
    kCandidate := BI_FromBytes_BE(t);

    // reduce mod (q-1) and add 1 -> ensures 1 <= k <= q-1
    bi_tmp := BI_Mod(kCandidate, qMinus1);
    BI_Free(kCandidate);
    kCandidate := BI_Add(bi_tmp, BI_One);
    BI_Free(bi_tmp);

  until (BI_Compare(kCandidate, BI_One) >= 0) and (BI_Compare(kCandidate, q) < 0);

  BI_Free(qMinus1);
  Result := kCandidate;
end;

{ ----------------------------
  === ECC Arithmetic: projective affine formulas (affine used for clarity)
  ---------------------------- }

procedure PointInit(out P: TECPoint);
begin
  P.X := nil;
  P.Y := nil;
  P.Infinity := True;
end;

procedure PointAssign(out A: TECPoint; const B: TECPoint);
begin
  if B.Infinity then
  begin
    A.Infinity := True;
    Exit;
  end;
  A.Infinity := False;
  A.X := BI_Copy(B.X);
  A.Y := BI_Copy(B.Y);
end;

procedure PointFree(var P: TECPoint);
begin
  if P.X <> nil then BI_Free(P.X);
  if P.Y <> nil then BI_Free(P.Y);
  P.Infinity := True;
  P.X := nil;
  P.Y := nil;
end;

function PointIsInfinity(const P: TECPoint): boolean;
begin
  Result := P.Infinity;
end;

function PointEqual(const A, B: TECPoint): boolean;
begin
  if A.Infinity and B.Infinity then Exit(True);
  if A.Infinity xor B.Infinity then Exit(False);
  Result := (BI_Compare(A.X, B.X) = 0) and (BI_Compare(A.Y, B.Y) = 0);
end;

procedure PointDouble(const P: TECPoint; out R: TECPoint);
var
  lambda, tmp1, tmp2, threeX2, twoY, invTwoY: TBIHandle;
begin
  PointInit(R);
  if P.Infinity then Exit;

  // lambda = (3*x^2 + a) / (2*y) mod p
  // tmp1 = x^2
  tmp1 := BI_MulMod(P.X, P.X, BI_p); // x^2
  threeX2 := BI_AddMod(tmp1, tmp1, BI_p); // 2*x^2
  threeX2 := BI_AddMod(threeX2, tmp1, BI_p); // 3*x^2
  tmp2 := BI_AddMod(threeX2, BI_a, BI_p); // 3*x^2 + a
  twoY := BI_AddMod(P.Y, P.Y, BI_p); // 2*y
  invTwoY := BI_InvMod(twoY, BI_p); // (2y)^-1
  lambda := BI_MulMod(tmp2, invTwoY, BI_p);

  // xr = lambda^2 - 2*x
  tmp1 := BI_MulMod(lambda, lambda, BI_p); // lambda^2
  tmp2 := BI_AddMod(P.X, P.X, BI_p); // 2*x
  R.X := BI_SubMod(tmp1, tmp2, BI_p);

  // yr = lambda*(x - xr) - y
  tmp1 := BI_SubMod(P.X, R.X, BI_p);
  tmp1 := BI_MulMod(lambda, tmp1, BI_p);
  R.Y := BI_SubMod(tmp1, P.Y, BI_p);

  // free temporaries
  BI_Free(tmp1);
  BI_Free(tmp2);
  BI_Free(threeX2);
  BI_Free(twoY);
  BI_Free(invTwoY);
  BI_Free(lambda);
end;

procedure PointAdd(const P, Q: TECPoint; out R: TECPoint);
var
  lambda, tmp1, tmp2, invTmp: TBIHandle;
begin
  PointInit(R);
  if P.Infinity then
  begin
    PointAssign(R, Q);
    Exit;
  end;
  if Q.Infinity then
  begin
    PointAssign(R, P);
    Exit;
  end;

  if (BI_Compare(P.X, Q.X) = 0) then
  begin
    if (BI_Compare(P.Y, Q.Y) = 0) then
    begin
      // P == Q -> doubling
      PointDouble(P, R);
      Exit;
    end
    else
    begin
      // P.x == Q.x but y != -> point at infinity
      R.Infinity := True;
      Exit;
    end;
  end;

  // lambda = (y2 - y1) / (x2 - x1)
  tmp1 := BI_SubMod(Q.Y, P.Y, BI_p); // y2 - y1
  tmp2 := BI_SubMod(Q.X, P.X, BI_p); // x2 - x1
  invTmp := BI_InvMod(tmp2, BI_p);
  lambda := BI_MulMod(tmp1, invTmp, BI_p);

  // xr = lambda^2 - x1 - x2
  tmp1 := BI_MulMod(lambda, lambda, BI_p);
  tmp2 := BI_AddMod(P.X, Q.X, BI_p);
  R.X := BI_SubMod(BI_SubMod(tmp1, P.X, BI_p), Q.X, BI_p);

  // yr = lambda*(x1 - xr) - y1
  tmp1 := BI_SubMod(P.X, R.X, BI_p);
  tmp1 := BI_MulMod(lambda, tmp1, BI_p);
  R.Y := BI_SubMod(tmp1, P.Y, BI_p);

  // free temporaries
  BI_Free(tmp1);
  BI_Free(tmp2);
  BI_Free(invTmp);
  BI_Free(lambda);
end;

procedure ScalarMultiply(const P: TECPoint; const k: TBIHandle; out R: TECPoint);
var
  Q: TECPoint;
  bitCount, i: integer;
  kCopy: TBIHandle;
  // We'll do double-and-add (left-to-right)
  kBytes: TBytes;
  totalBits, bIdx, byteIdx: integer;
  curBit: integer;
  tempP: TECPoint;
  tmp: TECPoint;
begin
  PointInit(R);
  if P.Infinity then Exit;
  kCopy := BI_Copy(k);
  Q.Infinity := True;
  Q.X := nil;
  Q.Y := nil;

  // find bitlength by converting to bytes (adapter must produce big-endian)
  // Simple algorithm: while kCopy > 0: if odd then Q = Q + P; P = 2P; k = k >> 1
  // We'll implement right-to-left binary
  // NOTE: adapter should support dividing by 2 or testing LSB; we don't have it,
  // so as a fallback do naive approach: repeatedly compare and subtract powers of 2.
  // To keep code compact and portable, use the following approach:
  // Convert k to bytes and iterate bits MSB->LSB

  kBytes := BI_ToBytes_BE(kCopy);
  totalBits := Length(kBytes) * 8;
  PointInit(R);
  tempP := P; // copy reference (we'll use Add/Double on copies)
  for bIdx := 0 to totalBits - 1 do
  begin
    // process MSB first
    byteIdx := bIdx div 8;
    if (kBytes[byteIdx] and (1 shl (7 - (bIdx mod 8)))) <> 0 then  curBit := bIdx;
    // double R
    if not R.Infinity then
    begin
      PointDouble(R, R); // R = 2*R
    end;
    if curBit <> 0 then
    begin
      if R.Infinity then PointAssign(R, P)
      else
      begin
        PointAdd(R, P, tmp);
        PointAssign(R, tmp);
        PointFree(tmp);
      end;
    end;
  end;

  BI_Free(kCopy);
end;

{ ----------------------------
  === ECDSA operations
---------------------------- }

procedure ECDSA_GenerateKey(out Priv: TBIHandle; out Pub: TECPoint);
var
  tmp: TECPoint;
begin
  tmp.X := BI_Gx;
  tmp.Y := BI_Gy;
  tmp.Infinity := False;
  // Priv: random in [1..n-1]
  Priv := BI_RandRange(BI_n);
  // Pub = Priv * G
  ScalarMultiply(tmp, Priv, Pub);
end;

procedure ECDSA_Sign(const Msg: Pointer; const MsgLen: nativeint; const Priv: TBIHandle;
  out Sig: TECDSASignature);
var
  hashBytes, privBytes: TBytes;
  k, r, s, kinv, tmp, e: TBIHandle;
  Px: TBIHandle;
  tmpP, P: TECPoint;
begin
  // Hash message with SHA-512
  hashBytes := SHA512_Short(Copy(TBytes(Msg^), 0, MsgLen)); // adapter: replace with proper conversion
  privBytes := BI_ToBytes_BE(Priv);

  // k = RFC6979(...) or random fallback
  k := RFC6979_GenerateK(privBytes, hashBytes, BI_n);

  // P = k * G
  PointInit(P);
  tmpP.X := BI_Gx;
  tmpP.Y := BI_Gy;
  tmpP.Infinity := False;

  ScalarMultiply(tmpP, k, P);

  // r = Px mod n
  r := BI_Copy(P.X); // then mod n: compute r = r mod n
  // For modular reduction we assume BI_MulMod with 1 does reduction; if not, adapter must provide reduction or mod function.
  // Here assume BI_MulMod(r, 1, n) gives r mod n:
  tmp := BI_One; // one
  r := BI_MulMod(r, tmp, BI_n);
  BI_Free(tmp);

  // s = k^-1 * (e + d*r) mod n
  kinv := BI_InvMod(k, BI_n);
  e := BI_FromBytes_BE(hashBytes);
  tmp := BI_MulMod(Priv, r, BI_n); // d*r
  tmp := BI_AddMod(e, tmp, BI_n);  // e + d*r
  s := BI_MulMod(kinv, tmp, BI_n);

  Sig.R := r;
  Sig.S := s;

  // free temporaries
  BI_Free(k);
  BI_Free(kinv);
  BI_Free(tmp);
  BI_Free(e);
  PointFree(P);
end;

function ECDSA_Verify(const Msg: Pointer; const MsgLen: nativeint; const Pub: TECPoint;
  const Sig: TECDSASignature): boolean;
var
  e, w, u1, u2, v, tmp: TBIHandle;
  tmpP, P1, P2, R: TECPoint;
  hashBytes: TBytes;
begin
  // Basic checks: r and s in [1..n-1]
  // TODO: check 0 < r < n and 0 < s < n using BI_Compare
  // Hash message
  hashBytes := SHA512_Short(Copy(TBytes(Msg^), 0, MsgLen));
  e := BI_FromBytes_BE(hashBytes);

  // w = s^-1 mod n
  w := BI_InvMod(Sig.S, BI_n);

  u1 := BI_MulMod(e, w, BI_n);
  u2 := BI_MulMod(Sig.R, w, BI_n);

  // P = u1*G + u2*Q
  PointInit(P1);
  PointInit(P2);
  tmpP.x := BI_Gx;
  tmpP.y := BI_Gy;
  tmpP.Infinity := False;
  ScalarMultiply(tmpP, u1, P1);
  ScalarMultiply(Pub, u2, P2);

  PointAdd(P1, P2, R);

  // v = R.x mod n
  tmp := BI_MulMod(R.X, BI_One, BI_n); // R.x mod n
  v := tmp;

  Result := BI_Compare(v, Sig.R) = 0;

  // free
  BI_Free(e);
  BI_Free(w);
  BI_Free(u1);
  BI_Free(u2);
  BI_Free(v);
  BI_Free(tmp);
  PointFree(P1);
  PointFree(P2);
  PointFree(R);
end;

{ ----------------------------
  === Encoding helpers ===
---------------------------- }

function EncodePointUncompressed(const P: TECPoint): TBytes;
var
  xLen, yLen, totalLen: integer;
begin
  if P.Infinity then
    raise Exception.Create('Cannot encode infinity point');

  xLen := BI_ByteLength(P.X);
  yLen := BI_ByteLength(P.Y);
  totalLen := 1 + xLen + yLen;

  SetLength(Result, totalLen);
  Result[0] := $04; // uncompressed point

  // Запис координат напряму через контекст
  BI_ToBytes_BE_Buffer(P.X, @Result[1]);
  BI_ToBytes_BE_Buffer(P.Y, @Result[1 + xLen]);
end;

function DecodePointUncompressed(const Buf: TBytes; out P: TECPoint): boolean;
var
  half: integer;
begin
  if (Length(Buf) < 1) or (Buf[0] <> $04) then Exit(False);

  // Довжини координат визначаємо як половину залишку байтів
  half := (Length(Buf) - 1) div 2;

  P.X := BI_FromBytes_BE_Ptr(@Buf[1], half);
  P.Y := BI_FromBytes_BE_Ptr(@Buf[1 + half], Length(Buf) - 1 - half);
  P.Infinity := False;
  Result := True;
end;

function EncodePointCompressed(const P: TECPoint): TBytes;
var
  xLen: integer;
  prefix: byte;
begin
  if P.Infinity then
    raise Exception.Create('Cannot encode infinity point');

  // Визначаємо префікс за парністю Y
  if BI_IsEven(P.Y) then
    prefix := $02
  else
    prefix := $03;

  xLen := BI_ByteLength(P.X);
  SetLength(Result, 1 + xLen);
  Result[0] := prefix;

  // Запис X напряму
  BI_ToBytes_BE_Buffer(P.X, @Result[1]);
end;


function DecodePointCompressed(const Buf: TBytes; Curve: PEC_Curve; out P: TECPoint): boolean;
var
  prefix: byte;
  x, y, tmp, pMinusY: PBigInt;
begin
  Result := False;
  if (Length(Buf) < 2) then Exit;

  prefix := Buf[0];
  if not (prefix in [$02, $03]) then Exit;

  // Відновлюємо X
  P.X := BI_FromBytes_BE_Ptr(@Buf[1], Length(Buf) - 1);

  // Y² = X³ + a*X + b mod p
  tmp := BI_ModPow(P.X, BI_FromUInt32(3), Curve^.P);        // X^3 mod p
  tmp := BI_MulMod(Curve^.A, P.X, Curve^.P);                     // tmp := tmp + a*X
  tmp := BI_AddMod(tmp, Curve^.B, Curve^.P);                           // tmp := tmp + b mod p
  y := BI_ModSqrt(tmp, Curve^.P);                               // y = sqrt(tmp) mod p

  if y = nil then Exit; // немає кореня ⇒ неправильна точка

  // Вибираємо корінь за префіксом
  if ((prefix = $02) and not BI_IsEven(y)) or ((prefix = $03) and BI_IsEven(y)) then
  begin
    pMinusY := BI_Sub(Curve^.P, y);  // y := p - y
    BI_Free(y);
    y := pMinusY;
  end;

  P.Y := y;
  P.Infinity := False;
  Result := True;
end;

{ ----------------------------
  === Initialization: load curve params
---------------------------- }

procedure LoadCurveParams;
begin
  if BI_p <> nil then Exit;
  BI_p := BI_FromHex_BE(HEX_p);
  BI_a := BI_FromHex_BE(HEX_a);
  BI_b := BI_FromHex_BE(HEX_b);
  BI_Gx := BI_FromHex_BE(HEX_Gx);
  BI_Gy := BI_FromHex_BE(HEX_Gy);
  BI_n := BI_FromHex_BE(HEX_n);
  BI_h := BI_FromHex_BE(HEX_h);
end;

initialization
  GlobalRsaContext := TRsaContext.Create;
  // nothing: user must call LoadCurveParams or call ECDSA_GenerateKey which will load.

finalization
  FreeAndNil(GlobalRsaContext);
end.
