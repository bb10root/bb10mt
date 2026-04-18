unit bbCGI;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils;

type
  TBBCGI = class
  private
    fIP: string;
    fPass: string;
    fAuthCookie: string;
  public
    procedure Connect(ip, password: string);
    procedure GetFile(path, pkgName, pkgId: string);
    procedure GetFileX(path: string);
    function DeviceInfo(): string;
    function GetProps(): string;
    function SetProp(Name, Value: string): string;
    procedure ListApps();

    procedure Install(Data: TFileStream; Name: string);

    procedure PutFileX(Data: TFileStream; Name: string);
    procedure PutFile(Data: TFileStream; fileName, pkgName, pkgId: string);

    procedure PutDebugToken(Data: TFileStream; Name: string);
    function Backup(): string;
    constructor Create;
  end;


implementation


uses
  StrUtils, ssl_openssl3, ssl_openssl3_lib, httpsend, synautil, synacode, blcksock,
  Laz2_DOM, laz2_XMLRead, uCrypto, uMisc;

type
  TFormData = class
  private
    Bound: string;
    Stream: TMemoryStream;
    function GetContentType: string;
    function GetData: string;
    procedure Finalize;
  public

    constructor Create;
    destructor Destroy; override;
    procedure AddFile(FieldName, FileName: string; Data: TFileStream; mime: string = '');
    procedure AddField(FieldName, FieldValue: string);
    property ContentType: string read GetContentType;
    property Data: string read getData;

  end;


  THTTPSendX = class(THTTPSend)
    constructor Create(authCookie: string); overload;
  end;


constructor THTTPSendX.Create(authCookie: string);
begin
  inherited Create;
  Sock.SSL.Ciphers := 'DEFAULT@SECLEVEL=0';
  UserAgent := 'QNXWebClient/1.0';
  if trim(authCookie) <> '' then
    Cookies.AddText(authCookie);
end;

destructor TFormData.Destroy;
begin
  Stream.Free;
  inherited;
end;


function TFormData.GetData: string;
begin
  Finalize();
  Stream.Seek(0, soBeginning);
  Result := ReadStrFromStream(Stream, Stream.Size);
end;

procedure TFormData.Finalize;
begin
  WriteStrToStream(Stream, '--' + Bound + '--' + CRLF);
end;

function TFormData.GetContentType: string;
begin
  Result := 'multipart/form-data; boundary=' + Bound;
end;

procedure TFormData.AddFile(FieldName, FileName: string; Data: TFileStream; mime: string = '');
var
  s: string;
begin
  WriteStrToStream(Stream, '--' + Bound + CRLF);
  s := 'content-disposition: form-data; name="' + FieldName + '";';
  s := s + ' filename="' + FileName + '"' + CRLF;
  if mime = '' then mime := 'Application/octet-string';
  s := s + 'Content-Type: ' + mime + CRLF + CRLF;
  WriteStrToStream(Stream, s);
  Stream.CopyFrom(Data, 0);
  WriteStrToStream(Stream, CRLF);
end;

procedure TFormData.AddField(FieldName, FieldValue: string);
var
  s: string;
begin
  WriteStrToStream(Stream, '--' + Bound + CRLF);
  s := 'content-disposition: form-data; name="' + FieldName + '"' + CRLF + CRLF;
  s := s + FieldValue + CRLF;
  WriteStrToStream(Stream, s);
end;


// (1000-14+8 -- 1000-6 +8
// 994 - 1002
constructor TFormData.Create;
begin
  Bound := StringOfChar('-', 16) + IntToHex(Random($7FFFFFFFFFFFFFFF), 16);
  Stream := TMemoryStream.Create;
end;


function hashAndEncode(password, salt, challenge: string; iters: integer): string;
var
  SaltBytes: TBytes;
  Hash1: TBytes;
  FinalInput: TBytes;
  FinalHash: TBytes;
  i: integer;
begin
  { salt: hex => bytes }
  SaltBytes := HexStringToBytes(salt);

  { H1 = HashPasswordV2(password_bytes) }
  Hash1 := HashPassV2(nil, SaltBytes, password, iters);

  { FinalInput = challenge_ascii || Hash1 }
  SetLength(FinalInput, Length(challenge) + Length(Hash1));
  if Length(challenge) > 0 then
    Move(challenge[1], FinalInput[0], Length(challenge));
  Move(Hash1[0], FinalInput[Length(challenge)], Length(Hash1));

  { H2 }
  FinalHash := HashPassV2(nil, SaltBytes, rawbytestring(FinalInput), iters);

  Result := BytesToHexString(FinalHash);
end;

constructor TBBCGI.Create;
begin
  fAuthCookie := '';
end;

function TBBCGI.DeviceInfo(): string;
var
  HTTP: THTTPSendX;
  form: TFormData;
begin
  HTTP := THTTPSendX.Create(fAuthCookie);
  try
    form := TFormData.Create;
    HTTP.MimeType := form.ContentType;
    form.AddField('command', 'List Device Info');
    WriteStrToStream(HTTP.Document, form.Data);
    form.Free;
    //HTTP.Document.SaveToFile('form.txt');
    if HTTP.HTTPMethod('POST', 'https://' + fIP + '/cgi-bin/appInstaller.cgi') then
      //if HTTP.HTTPMethod('POST', 'https://' + ip + '/cgi-bin/login.cgi') then
      Result := ReadStrFromStream(HTTP.Document, HTTP.Document.Size);
  finally
    HTTP.Free;
  end;

end;


function TBBCGI.GetProps(): string;
var
  HTTP: THTTPSendX;
  form: TFormData;
begin
  HTTP := THTTPSendX.Create(fAuthCookie);
  try
    form := TFormData.Create;
    HTTP.MimeType := form.ContentType;
    form.AddField('action', 'get');
    WriteStrToStream(HTTP.Document, form.Data);
    form.Free;
    if HTTP.HTTPMethod('POST', 'https://' + fip + '/cgi-bin/dynamicProperties.cgi') then
    begin
      HTTP.Document.SaveToFile('props_response.txt');
      HTTP.Document.Seek(0, soBeginning);
      Result := ReadStrFromStream(HTTP.Document, HTTP.Document.Size);

    end;
  finally
    HTTP.Free;
  end;

end;


function TBBCGI.Backup(): string;
var
  HTTP: THTTPSendX;
  form: TFormData;
begin
  HTTP := THTTPSendX.Create(fAuthCookie);
  try

    form := TFormData.Create;
    HTTP.MimeType := form.ContentType;
    //form.AddField('query', 'list');
    form.AddField('mode', 'settings');
    form.AddField('opt', 'rev2');
    WriteStrToStream(HTTP.Document, form.Data);
    form.Free;
    if HTTP.HTTPMethod('POST', 'https://' + fip + '/cgi-bin/backup.cgi') then
    begin
      //HTTP.Document.SaveToFile('bkp_response.txt');
      HTTP.Document.Seek(0, soBeginning);
      Result := ReadStrFromStream(HTTP.Document, HTTP.Document.Size);

    end;
  finally
    HTTP.Free;
  end;

end;


function TBBCGI.SetProp(Name, Value: string): string;
var
  HTTP: THTTPSendX;
  form: TFormData;
begin
  Result := '';
  HTTP := THTTPSendX.Create(fAuthCookie);
  try
    form := TFormData.Create;
    HTTP.MimeType := form.ContentType;
    form.AddField('action', 'set');
    form.AddField('name', Name);
    form.AddField('value', Value);
    WriteStrToStream(HTTP.Document, form.Data);
    form.Free;
    if HTTP.HTTPMethod('POST', 'https://' + fip + '/cgi-bin/dynamicProperties.cgi') then
    begin
      HTTP.Document.SaveToFile('setprop_response.txt');
      //      HTTP.Document.Seek(0, soBeginning);
      //      Result := ReadStrFromStream(HTTP.Document, HTTP.Document.Size);

    end;
  finally
    HTTP.Free;
  end;

end;


procedure TBBCGI.GetFile(path, pkgName, pkgId: string);
var
  HTTP: THTTPSendX;
  s: string;
  form: TFormData;
begin
  HTTP := THTTPSendX.Create(fAuthCookie);
  try
    form := TFormData.Create;
    HTTP.MimeType := form.ContentType;

    form.AddField('command', 'Get File');
    form.AddField('package_name', pkgName);
    form.AddField('package_id', pkgId);
    form.AddField('asset_path', path);

    WriteStrToStream(HTTP.Document, form.Data);
    form.Free;

    if HTTP.HTTPMethod('POST', 'https://' + fip + '/cgi-bin/appInstaller.cgi') then
      HTTP.Document.SaveToFile('response.txt');


  finally
    HTTP.Free;
  end;

end;

procedure TBBCGI.GetFileX(path: string);
begin
  GetFile('../../../../..' + path, 'sys.camera', 'gYABgAvGHb4h9H5WeWdjQhXgeRM');
end;


procedure TBBCGI.PutFile(Data: TFileStream; fileName, pkgName, pkgId: string);
var
  HTTP: THTTPSendX;
  s: string;
  form: TFormData;
begin
  HTTP := THTTPSendX.Create(fAuthCookie);
  try
    form := TFormData.Create;
    HTTP.MimeType := form.ContentType;

    form.AddField('command', 'Put File');
    form.AddField('package_name', pkgName);
    form.AddField('package_id', pkgId);
    form.AddField('asset_path', fileName);
    s := ExtractFileName(fileName);
    form.AddFile('file', s, Data);
    s := form.Data;
    WriteStrToStream(HTTP.Document, s);
    form.Free;
    //HTTP.Document.SaveToFile('form.txt');
    if HTTP.HTTPMethod('POST', 'https://' + fip + '/cgi-bin/appInstaller.cgi') then
      //HTTP.Document.SaveToFile('put_response.txt');

  finally
    HTTP.Free;
  end;

end;

procedure TBBCGI.ListApps();
var
  HTTP: THTTPSendX;
  s: string;
  form: TFormData;
begin
  HTTP := THTTPSendX.Create(fAuthCookie);
  try
    form := TFormData.Create;
    HTTP.MimeType := form.ContentType;

    form.AddField('command', 'List');
    s := form.Data;
    WriteStrToStream(HTTP.Document, s);
    form.Free;
    if HTTP.HTTPMethod('POST', 'https://' + fip + '/cgi-bin/appInstaller.cgi') then
      //HTTP.Document.SaveToFile('list_response.txt');

  finally
    HTTP.Free;
  end;

end;


procedure TBBCGI.PutFileX(Data: TFileStream; Name: string);
begin
  PutFile(Data, '../../../../..' + Name, 'sys.camera', 'gYABgAvGHb4h9H5WeWdjQhXgeRM');
end;


procedure TBBCGI.PutDebugToken(Data: TFileStream; Name: string);
var
  HTTP: THTTPSendX;
  s: string;
  form: TFormData;
begin
  HTTP := THTTPSendX.Create(fAuthCookie);
  try
    form := TFormData.Create;
    HTTP.MimeType := form.ContentType;
    form.AddField('command', 'Install Debug Token');
    form.AddFile('file', Name, Data, 'application/zip');
    s := form.Data;
    WriteStrToStream(HTTP.Document, s);
    form.Free;
    HTTP.Document.SaveToFile('form.txt');
    HTTP.HTTPMethod('POST', 'https://' + fip + '/cgi-bin/appInstaller.cgi');
    s := HTTP.ResultString;
    //HTTP.Document.SaveToFile('put_response.txt');
  finally
    HTTP.Free;
  end;
end;


procedure TBBCGI.Install(Data: TFileStream; Name: string);
var
  HTTP: THTTPSendX;
  s: string;
  form: TFormData;
begin
  HTTP := THTTPSendX.Create(fAuthCookie);
  try
    form := TFormData.Create;
    HTTP.MimeType := form.ContentType;
    form.AddField('command', 'Install');
    form.AddField('package_name', 'sys.firstlaunch');
    form.AddField('package_id', 'gYABgE1L_lY.sjW85E1SCBQsrco');
    form.AddFile('file', Name, Data, 'application/zip');
    s := form.Data;
    WriteStrToStream(HTTP.Document, s);
    form.Free;
    HTTP.Document.SaveToFile('form.txt');
    HTTP.HTTPMethod('POST', 'https://' + fip + '/cgi-bin/appInstaller.cgi');
    s := HTTP.ResultString;
    //HTTP.Document.SaveToFile('install_response.txt');
  finally
    HTTP.Free;
  end;

end;


procedure TBBCGI.Connect(ip, password: string);

  function GetNodeValue(Base: TDOMNode; Name: string): string;
  var
    PassNode: TDOMNode;
  begin
    Result := '';
    if Base <> nil then
    begin
      PassNode := Base.FindNode(Name);
      if PassNode <> nil then
      begin
        Result := PassNode.FirstChild.NodeValue;
        PassNode.Free;
      end;
    end;
  end;

var
  xml: TXMLDocument;
  HTTP: THTTPSendX;
  iCount: integer;
  url, salt, challenge, auth: string;
  Result: boolean;
var
  Node, Node2: TDOMNode;
begin
  fIP := ip;
  fPass := password;

  url := 'https://' + ip + '/cgi-bin/login.cgi';
  HTTP := THTTPSendX.Create('');
  try
    Result := HTTP.HTTPMethod('GET', url + '?request_version=1');
    if Result then
    begin
      ReadXMLFile(xml, HTTP.Document);
      HTTP.Document.SaveToFile('auth.xml');
      Node2 := xml.DocumentElement.FindNode('Auth');
      if Node2 = nil then

        Node2 := xml.DocumentElement.FindNode('AuthChallenge');

      Node := Node2.FindNode('Status');
      try
        salt := GetNodeValue(Node2, 'Salt');
        challenge := GetNodeValue(Node2, 'Challenge');
        iCount := StrToIntDef(GetNodeValue(Node2, 'ICount'), 0);

        auth := hashAndEncode(fpass, salt, challenge, iCount);
        fauthCookie := HTTP.Cookies.GetText;
        HTTP.Clear;
        Result := HTTP.HTTPMethod('GET', url + '?challenge_data=' + auth + '&request_version=1');
        fauthCookie := HTTP.Cookies.GetText;

      finally
        Node.Free;
        Node2.Free;
        xml.Free;
      end;
    end;
  finally
    HTTP.Free;
  end;

end;

initialization

end.
