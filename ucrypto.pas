unit uCrypto;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, mormot.crypt.core;

function BytesToHex(const Data: TBytes): string;
function HashPassV2(const Challenge, Salt: TBytes; const password: string; Iterations: integer): TBytes;


function SHA256OfStream(AStream: TStream): TSha256Digest;
function SHA256OfStreamHex(AStream: TStream): string;

function SHA512OfStream(AStream: TStream): TSha512Digest;
function SHA512OfStreamHex(AStream: TStream): string;

function Base64UrlEncode(const S: string): string;
function Base64UrlDecode(const S: string): string;


type
  TRsaBlockType = (btEncryption = 2, btSignature = 1);

function Pkcs1PadBytes(const Msg: TBytes; KeyLen: integer; BlockType: TRsaBlockType): TBytes;
function Pkcs1UnPadBytes(const Encoded: TBytes; BlockType: TRsaBlockType; out Decoded: TBytes): boolean;

function PKCS7UnPad(const Data: TBytes; BlockSize: integer): TBytes;
function PKCS7Pad(const Data: TBytes; BlockSize: integer): TBytes;

implementation

uses ecdsa_p521, base64;

function BytesToHex(const Data: TBytes): string;
var
  i: integer;
begin
  Result := '';
  for i := 0 to Length(Data) - 1 do
    Result := Result + IntToHex(Data[i], 2);
end;


function SHA256OfStream(AStream: TStream): TSha256Digest;
var
  xSHA256: TSha256;
  Buffer: array[0..8191] of byte;
  ReadBytes: integer;
  I: integer;
begin
  xSHA256.Init;
  AStream.Position := 0;
  repeat
    ReadBytes := AStream.Read(Buffer, SizeOf(Buffer));
    if ReadBytes > 0 then
      xSHA256.Update(@Buffer[0], ReadBytes);
  until ReadBytes = 0;
  xSHA256.Final(Result);
end;


function SHA256OfStreamHex(AStream: TStream): string;
var
  Digest: TSHA256Digest;
  I: integer;
begin
  Digest := SHA256OfStream(AStream);
  Result := '';
  for I := 0 to High(Digest) do
    Result := Result + LowerCase(IntToHex(Digest[I], 2));
end;


function SHA512OfStream(AStream: TStream): TSha512Digest;
var
  xSHA512: TSha512;
  Buffer: array[0..8191] of byte;
  ReadBytes: integer;
  I: integer;
begin
  xSHA512.Init;
  AStream.Position := 0;
  repeat
    ReadBytes := AStream.Read(Buffer, SizeOf(Buffer));
    if ReadBytes > 0 then
      xSHA512.Update(@Buffer[0], ReadBytes);
  until ReadBytes = 0;
  xSHA512.Final(Result);
end;


function SHA512OfStreamHex(AStream: TStream): string;
var
  Digest: TSHA512Digest;
  I: integer;
begin
  Digest := SHA512OfStream(AStream);
  Result := '';
  for I := 0 to High(Digest) do
    Result := Result + LowerCase(IntToHex(Digest[I], 2));
end;


function HashPassV2(const Challenge, Salt: TBytes; const password: string; Iterations: integer): TBytes;
var
  HashedData: TBytes;
  Count: integer;
  Challenger: boolean;
  Buf: TBytes;
  Offset: integer;
  Digest: TSha512Digest;
  xSHA512: TSHA512;
begin
  SetLength(HashedData, Length(Password));
  if Length(Password) > 0 then
    Move(Password[1], HashedData[0], Length(Password));

  Count := 0;
  Challenger := True;

  repeat
    SetLength(Buf, 4 + Length(Salt) + Length(HashedData));
    Offset := 0;

    Buf[0] := Count and $FF;
    Buf[1] := (Count shr 8) and $FF;
    Buf[2] := (Count shr 16) and $FF;
    Buf[3] := (Count shr 24) and $FF;
    Offset := 4;

    if Length(Salt) > 0 then
    begin
      Move(Salt[0], Buf[Offset], Length(Salt));
      Inc(Offset, Length(Salt));
    end;


    if Length(HashedData) > 0 then
      Move(HashedData[0], Buf[Offset], Length(HashedData));

    if Count = 0 then
      SetLength(HashedData, 64);

    xSHA512.Full(@Buf[0], length(Buf), Digest);
    if Length(HashedData) < SizeOf(Digest) then
      SetLength(HashedData, SizeOf(Digest));
    move(Digest, HashedData[0], SizeOf(Digest));

    if (Count = Iterations - 1) and Challenger then
    begin
      Count := -1;
      Challenger := False;
      // Prepend challenge to hashedData
      if Length(Challenge) > 0 then
      begin
        SetLength(Buf, Length(Challenge) + Length(HashedData));
        Move(Challenge[0], Buf[0], Length(Challenge));
        if Length(HashedData) > 0 then
          Move(HashedData[0], Buf[Length(Challenge)], Length(HashedData));
        HashedData := Copy(Buf, 0, Length(Buf));
      end;
    end;

    Inc(Count);
  until Count >= Iterations;

  Result := HashedData;
end;


function Base64UrlEncode(const S: string): string;
begin
  Result := EncodeStringBase64(S);
  // Замінюємо символи для URL-safe
  Result := StringReplace(Result, '+', '-', [rfReplaceAll]);
  Result := StringReplace(Result, '/', '_', [rfReplaceAll]);
  // Видаляємо '='
  while (Length(Result) > 0) and (Result[Length(Result)] = '=') do
    SetLength(Result, Length(Result) - 1);
end;

function Base64UrlDecode(const S: string): string;
var
  B64: string;
begin
  B64 := S;
  // Відновлюємо символи
  B64 := StringReplace(B64, '-', '+', [rfReplaceAll]);
  B64 := StringReplace(B64, '_', '/', [rfReplaceAll]);
  // Відновлюємо '=' для кратності 4
  while (Length(B64) mod 4) <> 0 do
    B64 := B64 + '=';
  Result := DecodeStringBase64(B64);
end;

{===========================================================
  PKCS#1 v1.5 Padding
  M -> EM = 0x00 || BT || PS || 0x00 || M
===========================================================}
function Pkcs1PadBytes(const Msg: TBytes; KeyLen: integer; BlockType: TRsaBlockType): TBytes;
var
  PSLen, i: integer;
begin
  if KeyLen < Length(Msg) + 11 then
    raise Exception.Create('Message too long for RSA key size');

  SetLength(Result, KeyLen);
  Result[0] := 0;
  case BlockType of
    btSignature: Result[1] := 1;
    btEncryption: Result[1] := 2;
  end;

  PSLen := KeyLen - Length(Msg) - 3;

  case BlockType of
    btSignature:
      for i := 0 to PSLen - 1 do
        Result[2 + i] := $FF;
    btEncryption:
      for i := 0 to PSLen - 1 do
        repeat
          Result[2 + i] := byte(Random(255) + 1); // 1..255
        until Result[2 + i] <> 0;
  end;

  Result[2 + PSLen] := 0; // роздільник
  Move(Msg[0], Result[3 + PSLen], Length(Msg));
end;

{===========================================================
  PKCS#1 v1.5 Unpadding
  EM = 0x00 || BT || PS || 0x00 || M -> M
===========================================================}
function Pkcs1UnPadBytes(const Encoded: TBytes; BlockType: TRsaBlockType; out Decoded: TBytes): boolean;
var
  i, PSLen, MsgStart: integer;
begin
  Decoded := nil;
  Result := False;

  if Length(Encoded) < 11 then Exit; // мінімальна довжина

  if Encoded[0] <> 0 then Exit;

  case BlockType of
    btSignature: if Encoded[1] <> 1 then Exit;
    btEncryption: if Encoded[1] <> 2 then Exit;
  end;

  i := 2;
  case BlockType of
    btSignature:
    begin
      while (i < Length(Encoded)) and (Encoded[i] = $FF) do Inc(i);
      PSLen := i - 2;
      if PSLen < 8 then Exit;
    end;
    btEncryption:
    begin
      while (i < Length(Encoded)) and (Encoded[i] <> 0) do Inc(i);
      PSLen := i - 2;
      if PSLen < 8 then Exit;
    end;
  end;

  if (i >= Length(Encoded)) or (Encoded[i] <> 0) then Exit;

  Inc(i); // початок повідомлення
  MsgStart := i;
  SetLength(Decoded, Length(Encoded) - MsgStart);
  Move(Encoded[MsgStart], Decoded[0], Length(Encoded) - MsgStart);

  Result := True;
end;


function PKCS7Pad(const Data: TBytes; BlockSize: integer): TBytes;
var
  PadLen, i: integer;
begin
  PadLen := BlockSize - (Length(Data) mod BlockSize);
  if PadLen = 0 then
    PadLen := BlockSize; // повний блок padding, якщо вже кратне

  SetLength(Result, Length(Data) + PadLen);
  Move(Data[0], Result[0], Length(Data));
  for i := Length(Data) to Length(Result) - 1 do
    Result[i] := byte(PadLen);
end;

function PKCS7UnPad(const Data: TBytes; BlockSize: integer): TBytes;
var
  PadLen, i: integer;
begin
  if (Length(Data) = 0) or (Length(Data) mod BlockSize <> 0) then
    raise Exception.Create('Invalid padded data length');

  PadLen := Data[High(Data)];
  if (PadLen < 1) or (PadLen > BlockSize) then
    raise Exception.Create('Invalid PKCS#7 padding');

  // Перевірка усіх байт padding
  for i := Length(Data) - PadLen to Length(Data) - 1 do
    if Data[i] <> PadLen then
      raise Exception.Create('Invalid PKCS#7 padding bytes');

  SetLength(Result, Length(Data) - PadLen);
  Move(Data[0], Result[0], Length(Result));
end;


end.
