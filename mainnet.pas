unit MainNet;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, blcksock, synsock,
  synautil, mormot.crypt.core,
  mormot.crypt.rsa,
  mormot.core.base, mormot.core.os, Logger;

const
  KEEPALIVE_INTERVAL = 5000; // ms

  // Connection States
  DISCONNECTED = 0;
  CONNECTING = 1;
  NEGOTIATED = 2;
  AUTHORISED = 3;
  AUTHENTICATED = 4;
  SSH_ACCEPTED = 5;
  COMPLETE = 6;


  CHALLENGE_ITEM_PIN = 1;
  CHALLENGE_ITEM_SESSIONKEY = 2;
  CHALLENGE_ITEM_BSN = 3;
  CHALLENGE_ITEM_PERMISSION = 4;

type

  TMainNet = class;

  TSocketThread = class(TThread)
  private
    FMainNet: TMainNet;
  protected
    procedure Execute; override;
  public
    constructor Create(AMainNet: TMainNet);
  end;

  TMainNet = class(TObject)
  private
    FSocket: TTCPBlockSocket;
    FSocketThread: TSocketThread;

    FPassword: string;
    FWrongPass: boolean;
    FIP: string;
    FState: integer;
    FConnState: integer;
    FLastKeepAlive: int64;
    FBBExists: boolean;
    FKeyExists: boolean;
    FLoggedIn: boolean;
    FWifiLoggedIn: boolean;
    FRestoring: boolean;
    FSSHKey: string;
    FLog: TLogManager;
    // Challenge response data
    FSessionKey: TBytes;
    FPrivKey: TRsaPrivateKey;
    FHashedPassword: ansistring;
    procedure AESEncryptSend(const Plain: TBytes; Code: word);
    procedure DoKeepAlive;
    procedure KeepAlive;
    procedure SocketLoop;
    procedure RequestConfigure;
    procedure RequestChallenge;
    procedure ReplyChallenge(ServerChallenge: rawbytestring);
    procedure RequestAuthenticate;
    procedure StartServices;
    procedure Authorise(Data: TBytes);
    procedure SendSSHKey;
    procedure OnSocketConnect;
    procedure OnSocketDisconnect;
    procedure OnSocketRead(Data: TBytes);
    procedure ProcessServerChallenge(const Data: TBytes);
  public
    constructor Create(Log: TLogManager = nil);
    destructor Destroy; override;

    procedure Init;
    procedure TargetClose;
    procedure EndConnection;

    property Password: string read FPassword write FPassword;
    property WrongPass: boolean read FWrongPass write FWrongPass;
    property IP: string read FIP write FIP;
    property SSHKey: string read FSSHKey write FSSHKey;
    property State: integer read FState write FState;
    property Detail: integer read FConnState;
    property BBExists: boolean read FBBExists write FBBExists;
    property KeyExists: boolean read FKeyExists write FKeyExists;
  end;

implementation

uses uCrypto, CLI.Console;       // Optional: Colored console output

  {------------------ TSocketThread ------------------}

constructor TSocketThread.Create(AMainNet: TMainNet);
begin
  inherited Create(False);
  FreeOnTerminate := False;
  FMainNet := AMainNet;
end;

procedure TSocketThread.Execute;
begin
  if Assigned(FMainNet) then
    FMainNet.SocketLoop;
end;

type
  TTargetCode = (
    tcHello = 1,
    tcFeedback = 2,
    tcStartRequest = 3,
    tcEncryptedChallengeResponse = 4,
    tcDecryptedChallengeResponse = 5,
    tcKeepAlive = 6,
    tcSendSSHKey = 7,
    tcAuthenticateChallengeRequest = 8,
    tcAuthenticateChallengeResponse = 9,
    tcAuthenticate = 10,
    tcStartServices = 11,
    tcClose = 12
    );

  TTargetFeedback = (
    tfResponseOK = 0,
    tfUnexpectedCommand = 1,
    tfChallengeFailure = 2,
    tfVersionMismatch = 10,
    tfNoPasswordRequired = 17
    );

  {------------------ TMainNet ------------------}

constructor TMainNet.Create(Log: TLogManager = nil);
begin
  inherited Create;
  FSocket := TTCPBlockSocket.Create;
  FState := 0;
  FConnState := DISCONNECTED;
  FRestoring := False;
  FLoggedIn := False;
  FLog := Log;
  FWifiLoggedIn := False;
  FBBExists := False;
  FKeyExists := False;
  FSocketThread := nil;
  FLastKeepAlive := GetTickCount64();
end;

destructor TMainNet.Destroy;
begin
  EndConnection;
  FSocket.Free;
  inherited Destroy;
end;

procedure TMainNet.Init;
begin
  FState := 1;
  FConnState := CONNECTING;
  FLog.AddMessage(Format('Connecting to target %s:4455', [ip]));

  FSocket.Connect(FIP, '4455');
  if FSocket.LastError = 0 then
  begin
    OnSocketConnect;
    FSocketThread := TSocketThread.Create(Self);
  end
  else
  begin
    FLog.AddMessage('Connection failed: ' + FSocket.LastErrorDesc);
    FState := 0;
    FConnState := DISCONNECTED;
  end;
end;

procedure TMainNet.EndConnection;
begin
  TargetClose;
  FState := 0;
  FConnState := DISCONNECTED;

  if Assigned(FSocketThread) then
  begin
    FSocketThread.Terminate;
    FSocketThread.WaitFor;
    FSocketThread.Free;
    FSocketThread := nil;
  end;

  FSocket.CloseSocket;
end;

procedure TMainNet.SocketLoop;
var
  Data: TBytes;
  BytesRead: integer;
begin
  SetLength(Data, 4096);
  while (FState > 0) and (not Assigned(FSocketThread) or not FSocketThread.Terminated) do
  begin
    if FSocket.CanRead(1000) then
    begin
      BytesRead := FSocket.RecvBuffer(@Data[0], Length(Data));
      if BytesRead > 0 then
      begin
        OnSocketRead(Data);
      end;
    end;

    //DoKeepAlive;
    Sleep(10);
  end;
end;

procedure TMainNet.DoKeepAlive;
var
  Now: QWord;
begin
  Now := GetTickCount64();
  if (FConnState >= COMPLETE) and ((Now - FLastKeepAlive) >= KEEPALIVE_INTERVAL) then
  begin
    KeepAlive;
    FLastKeepAlive := Now;
  end;
end;

procedure TMainNet.OnSocketConnect;
begin
  if FState > 0 then
    RequestConfigure
  else
    FBBExists := True;
end;

procedure TMainNet.OnSocketDisconnect;
begin
  FState := 0;
  FConnState := DISCONNECTED;
end;


procedure TMainNet.SendSSHKey;
var
  keyLength: word;
  packet: array of byte;
  i: integer;
begin
  FLog.AddMessage('Successfully authenticated with target credentials.');
  FLog.AddMessage('Sending ssh key to target');

  // Construct packet with key length and key data
  keyLength := Length(FSSHKey);

  // Create packet as byte array
  SetLength(packet, 2 + Length(FSSHKey));
  PWord(@packet[0])^ := NtoBE(word(Length(FSSHKey)));
  move(FSSHKey[1], packet[2], Length(FSSHKey));

  // Send buffer directly
  AESEncryptSend(packet, 7);
end;

procedure TMainNet.ProcessServerChallenge(const Data: TBytes);
var
  EntireLength, Version, Code, SourceLength, SessionKeyLength, SessionKeyType,
  ContainerLength, ContainerPrimitive, ContainerType, ExpectedSignatureLength, ExpectedSignatureType: word;
  ContainerKeyVersion: cardinal;
  SourceName, EncryptedBlob: TBytes;
  ServerChallenge: rawbytestring;
  RSA: TRsa;
begin
  FLog.AddMessage(Format('Authenticating with target %s:4455', [FIP]));

  // Р§РёС‚Р°С”РјРѕ Р·Р°РіРѕР»РѕРІРєРё С‚Р° РЅРµРІРёРєРѕСЂРёСЃС‚РѕРІСѓРІР°РЅС– РїРѕР»СЏ
  EntireLength := BEtoN(PWord(@Data[0])^);
  Version := BEtoN(PWord(@Data[2])^);
  Code := BEtoN(PWord(@Data[4])^);

  // РџСЂРѕРїСѓСЃРєР°С”РјРѕ 2 РЅРµРІС–РґРѕРјС– word
  // SessionKeyLength := LEtoN(PWord(@Data[8])^);
  // С‚РёРјС‡Р°СЃРѕРІРѕ РІРёРєРѕСЂРёСЃС‚Р°РЅРѕ РґР»СЏ РїСЂРѕРїСѓСЃРєСѓ
  SourceLength := LEtoN(PWord(@Data[10])^);
  SessionKeyLength := LEtoN(PWord(@Data[12])^);
  SessionKeyType := LEtoN(PWord(@Data[14])^);
  ContainerLength := LEtoN(PWord(@Data[16])^);
  ContainerPrimitive := LEtoN(PWord(@Data[18])^);
  ContainerType := LEtoN(PWord(@Data[20])^);
  ExpectedSignatureLength := LEtoN(PWord(@Data[22])^);
  ExpectedSignatureType := LEtoN(PWord(@Data[24])^);
  ContainerKeyVersion := LEtoN(PCardinal(@Data[26])^);

  // Р§РёС‚Р°С”РјРѕ sourceName
  SetLength(SourceName, SourceLength);
  if SourceLength > 0 then
    Move(Data[30], SourceName[0], SourceLength);

  // Р§РёС‚Р°С”РјРѕ encryptedBlob
  SetLength(EncryptedBlob, ContainerLength);
  if ContainerLength > 0 then
    Move(Data[30 + SourceLength], EncryptedBlob[0], ContainerLength);

  // Р РѕР·С€РёС„СЂРѕРІСѓС”РјРѕ РїСЂРёРІР°С‚РЅРёРј РєР»СЋС‡РµРј
  RSA := TRsa.Create;
  try
    RSA.LoadFromPrivateKey(FPrivKey);
    ServerChallenge := RSA.Pkcs1Decrypt(@EncryptedBlob[0]);
  finally
    FreeAndNil(RSA);
  end;

  // Р’РёРєР»РёРє С„СѓРЅРєС†С–С— РѕР±СЂРѕР±РєРё РІС–РґРїРѕРІС–РґС–
  replyChallenge(ServerChallenge);
end;

procedure TMainNet.OnSocketRead(Data: TBytes);
var
  packetLength, version, code, len: word;
  fcode: TTargetFeedback;
  Txt: string;
begin
  if Length(Data) >= 6 then
  begin
    packetLength := BEtoN(PWord(@Data[0])^);
    version := BEtoN(PWord(@Data[2])^);
    code := BEtoN(PWord(@Data[4])^);

    case TTargetCode(code) of
      tcFeedback: begin
        fcode := TTargetFeedback(BEtoN(PWord(@Data[6])^));
        len := BEtoN(PWord(@Data[8])^);
        SetLength(txt, len);
        if len > 0 then
          move(Data[10], Txt[1], len);
        if (fcode = tfResponseOK) then
        begin
          if FConnState = CONNECTING then
          begin
            RequestChallenge;
            FConnState := NEGOTIATED;
          end
          else
          begin
            if FConnState > COMPLETE then Exit;
            if FConnState <> COMPLETE then
            begin
              Inc(FConnState);
              if FConnState = COMPLETE then
                FLog.AddMessage(
                  'Successfully connected. This application must remain running in order to use debug tools. Exiting the application will terminate this connection.');
            end;
            case FConnState of
              AUTHORISED: RequestAuthenticate;
              AUTHENTICATED: SendSSHKey;
              SSH_ACCEPTED: begin
                FLog.AddMessage('ssh key successfully transferred.');
                StartServices;
              end;
              COMPLETE: KeepAlive;
            end;

          end;

        end;

      end;
      tcEncryptedChallengeResponse: begin

        ProcessServerChallenge(Data);
      end;
      tcAuthenticateChallengeResponse: begin
        Authorise(Data);
      end;
    end;
  end;
end;

procedure TMainNet.RequestConfigure;
var
  packet: array[0..5] of byte;
begin
  PWord(@packet[0])^ := NtoBE(word(6));
  PWord(@packet[2])^ := NtoBE(word(2));
  PWord(@packet[4])^ := NtoBE(word(tcHello));
  FSocket.SendBuffer(@packet[0], Length(packet));
end;

procedure TMainNet.RequestAuthenticate;
var
  packet: array[0..5] of byte;
begin
  PWord(@packet[0])^ := NtoBE(word(6));
  PWord(@packet[2])^ := NtoBE(word(2));
  PWord(@packet[4])^ := NtoBE(word(tcAuthenticateChallengeRequest));
  FSocket.SendBuffer(@packet[0], Length(packet));
end;

procedure TMainNet.StartServices;
var
  packet: array[0..5] of byte;
begin
  PWord(@packet[0])^ := NtoBE(word(6));
  PWord(@packet[2])^ := NtoBE(word(2));
  PWord(@packet[4])^ := NtoBE(word(tcStartServices));
  FSocket.SendBuffer(@packet[0], Length(packet));
end;

procedure TMainNet.KeepAlive;
var
  packet: array[0..5] of byte;
begin
  PWord(@packet[0])^ := NtoBE(word(6));
  PWord(@packet[2])^ := NtoBE(word(2));
  PWord(@packet[4])^ := NtoBE(word(tcKeepAlive));
  FSocket.SendBuffer(@packet[0], Length(packet));
  Sleep(1000);
end;

procedure TMainNet.TargetClose;
var
  packet: array[0..5] of byte;
begin
  PWord(@packet[0])^ := NtoBE(word(6));
  PWord(@packet[2])^ := NtoBE(word(2));
  PWord(@packet[4])^ := NtoBE(word(tcClose));
  FSocket.SendBuffer(@packet[0], Length(packet));
end;

{------------------------- RequestChallenge -------------------------}
procedure TMainNet.RequestChallenge;
var
  Rsa: TRsa;
  PubKey: TRsaPublicKey;
  Packet: TBytes;
  i: integer;
begin
  // РЎС‚РІРѕСЂСЋС”РјРѕ С– РіРµРЅРµСЂСѓС”РјРѕ RSA 1024-Р±С–С‚РЅРёР№ РєР»СЋС‡
  Rsa := TRsa.Create;
  try
    Rsa.Generate(1024); // Р°РЅР°Р»РѕРі RSA_generate_key_ex

    // Р—Р±РµСЂС–РіР°С”РјРѕ РїСѓР±Р»С–С‡РЅРёР№ РєР»СЋС‡ (ASN.1 DER Р°Р±Рѕ РЅР°С€ С„РѕСЂРјР°С‚)
    PubKey := Rsa.SavePublicKey;

    // РћС‚СЂРёРјСѓС”РјРѕ modulus (n) Сѓ big-endian
    if Length(PubKey.Modulus) > 128 then
      raise Exception.Create('Modulus > 128 bytes!');

    // Р¤РѕСЂРјСѓС”РјРѕ РїР°РєРµС‚ (8 Р±Р°Р№С‚ Р·Р°РіРѕР»РѕРІРѕРє + 128 Р±Р°Р№С‚ modulus)
    SetLength(Packet, 8 + Length(PubKey.Modulus));
    PWord(@Packet[0])^ := NtoBE(word(8 + Length(PubKey.Modulus)));
    PWord(@Packet[2])^ := NtoBE(word(2));
    PWord(@Packet[4])^ := NtoBE(word(3));
    PWord(@Packet[6])^ := NtoBE(word(Length(PubKey.Modulus)));

    move(PubKey.Modulus[1], Packet[8], Length(PubKey.Modulus));

    // Р’С–РґРїСЂР°РІР»СЏС”РјРѕ РїРѕ СЃРѕРєРµС‚Сѓ
    FSocket.SendBuffer(@Packet[0], Length(Packet));

    // Р—Р±РµСЂС–РіР°С”РјРѕ РїСЂРёРІР°С‚РЅРёР№ РєР»СЋС‡ Сѓ РїРѕР»С– РєР»Р°СЃСѓ
    Rsa.SavePrivateKey(FPrivKey); // РјРѕР¶РЅР° Сѓ PEM С‡Рё DER
  finally
    Rsa.Free;
  end;
end;

{------------------------- ReplyChallenge -------------------------}
procedure TMainNet.ReplyChallenge(ServerChallenge: rawbytestring);

  function getChallengeItem(itemId: byte): TBytes;
  var
    len, _itemID: byte;
    i, c: integer;
  begin
    SetLength(Result, 0);
    i := 1;
    c := Length(ServerChallenge);
    len := 0;
    _itemID := 0;
    while i <= c do
    begin
      if len = 0 then
        len := byte(ServerChallenge[i])
      else if _itemID = 0 then
        _itemID := byte(ServerChallenge[i])
      else
      begin
        if (_itemID = itemId) then
        begin
          SetLength(Result, len);
          move(ServerChallenge[i], Result[0], len);
          Exit;
        end;
        Inc(i, len - 1);
        len := 0;
        _itemID := 0;
      end;
      Inc(i);

    end;

  end;

const
  QCONNDOOR_PERMISSIONS: array[0..4] of byte = (3, 4, 118, 131, 1);
  EMSA_SHA1_HASH: array[0..14] of byte = (48, 33, 48, 9, 6, 5, 43, 14, 3, 2, 26, 5, 0, 4, 20);
var
  decryptedBlob, HashBuf: TBytes;
  Len: integer;
  Plain: TBytes;
  xSHA1: TSha1;
  Digest: TSha1Digest;
  Rsa: TRsa;
  Signature: rawbytestring;
begin
  // Build challenge buffer: serverChallenge + permissions

  FSessionKey := getChallengeItem(CHALLENGE_ITEM_SESSIONKEY);

  // Extract session key (bytes 8..23)
  //Move(decryptedBlob[8], FSessionKey[0], 16);

  SetLength(decryptedBlob, 30 + 5);
  Move(ServerChallenge[1], decryptedBlob[0], 30);
  Move(QCONNDOOR_PERMISSIONS[0], decryptedBlob[30], 5);

  // SHA1 hash
  SetLength(HashBuf, 35);
  Move(EMSA_SHA1_HASH[0], HashBuf[0], SizeOf(EMSA_SHA1_HASH));

  xSHA1.Init;
  xSHA1.Update(@decryptedBlob[0], 35);
  xSHA1.Final(Digest);
  Move(Digest[0], HashBuf[SizeOf(EMSA_SHA1_HASH)], 20);
  // RSA sign
  Rsa := TRsa.Create;
  try
    Rsa.LoadFromPrivateKey(FPrivKey);
    Signature := Rsa.Pkcs1Sign(@HashBuf[0], Length(HashBuf));
  finally
    Rsa.Free;
  end;

  // Construct plain text
  SetLength(Plain, 12 + Length(decryptedBlob) + Length(Signature));
  PWord(@Plain[0])^ := NtoBE(word(4 + Length(decryptedBlob) + Length(Signature)));
  PWord(@Plain[2])^ := NtoBE(word(Length(decryptedBlob)));
  PWord(@Plain[4])^ := NtoBE(word(Length(Signature)));

  Move(decryptedBlob[0], Plain[6], Length(decryptedBlob));
  Move(Signature[1], Plain[6 + Length(decryptedBlob)], Length(Signature));

  FLog.AddMessage('Authenticating with target credentials.');
  AESEncryptSend(Plain, word(tcDecryptedChallengeResponse));
end;

{------------------------- AES Encrypt & Send -------------------------}
procedure TMainNet.AESEncryptSend(const Plain: TBytes; Code: word);
var
  Encrypted: TBytes;
  Packet, Header, FullPacket: TBytes;
  TotalLen: integer;
  AES: TAesCbc;
  IV: TAesBlock;
  OutLen: integer;
begin
  // Р“РµРЅРµСЂСѓС”РјРѕ IV 16 Р±Р°Р№С‚
  AES := TAesCbc.Create(FSessionKey);
  try
    // РџС–РґРіРѕС‚РѕРІРєР° AES-128-CBC С€РёС„СЂСѓРІР°РЅРЅСЏ
    RandomBytes(@AES.IV[0], SizeOf(IV));
    move(AES.IV[0], IV[0], SizeOf(IV));
    Encrypted := AES.EncryptPkcs7(Plain);
  finally
    FreeAndNil(AES);
  end;

  // Р¤РѕСЂРјСѓС”РјРѕ РІРЅСѓС‚СЂС–С€РЅС–Р№ РїР°РєРµС‚: qint16(total) + qint16(plain len) + IV + encrypted
  SetLength(Packet, 4 + 16 + Length(Encrypted));
  Pword(@Packet[0])^ := NtoBE(word(Length(Encrypted)));
  Pword(@Packet[2])^ := NtoBE(word(Length(Plain)));
  Move(IV[0], Packet[4], 16);
  Move(Encrypted[0], Packet[20], Length(Encrypted));
  //Move(Encrypted[0], Packet[4], Length(Encrypted));

  // Р—Р°РіРѕР»РѕРІРѕРє РґР»СЏ СЃРѕРєРµС‚Р°
  SetLength(Header, 6);

  // РћР±вЂ™С”РґРЅСѓС”РјРѕ Р·Р°РіРѕР»РѕРІРѕРє + РїР°РєРµС‚
  TotalLen := Length(Header) + Length(Packet);
  PWord(@Header[0])^ := NtoBE(word(TotalLen));
  PWord(@Header[2])^ := NtoBE(word(2));
  PWord(@Header[4])^ := NtoBE(word(Code));

  SetLength(FullPacket, TotalLen);
  Move(Header[0], FullPacket[0], Length(Header));
  Move(Packet[0], FullPacket[Length(Header)], Length(Packet));

  // Р’С–РґРїСЂР°РІРєР°
  FSocket.SendBuffer(@FullPacket[0], Length(FullPacket));
end;

{------------------------- Authorise -------------------------}
procedure TMainNet.Authorise(Data: TBytes);
var
  Plain: TBytes;

  Algo, Iterations: integer;
  SaltLength: smallint;
  ChallengeLength: smallint;
  Salt: TBytes;
  Challenge: TBytes;
  HashedData: TBytes;
begin

  Algo := BEtoN(PInteger(@Data[6])^);
  Iterations := BEtoN(PInteger(@Data[10])^);
  SaltLength := BEtoN(PWord(@Data[14])^);
  ChallengeLength := BEtoN(PWord(@Data[16])^);

  SetLength(Salt, SaltLength);
  SetLength(Challenge, ChallengeLength);

  move(Data[18], Salt[0], SaltLength);
  move(Data[18 + SaltLength], Challenge[0], ChallengeLength);

  HashedData := HashPassV2(Challenge, Salt, FPassword, Iterations);

  FHashedPassword := UpperCase(BytesToHex(HashedData));

  SetLength(Plain, 2 + Length(FHashedPassword));
  PWord(@Plain[0])^ := NtoBE(word(Length(FHashedPassword)));
  Move(FHashedPassword[1], Plain[2], Length(FHashedPassword));
  AESEncryptSend(Plain, word(tcAuthenticate));
end;

end.
