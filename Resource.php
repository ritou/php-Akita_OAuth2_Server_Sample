<?php

// This is OAuth 2.0 Sample Protected Resource

// process Request
require_once './lib/DataHandler.php';

// process request
$headers = apache_request_headers();
$request = new Akita_OAuth2_Server_Request('resource', $_SERVER, $_GET, $headers);
$dataHandler = new Akita_OAuth2_Server_Sample_DataHandler($request);
$resource = new Akita_OAuth2_Server_ProtectedResource();
try{
    $authInfo = $resource->processRequest($dataHandler);
}catch(Akita_OAuth2_Server_Error $error){
    // error handling
    header('HTTP/1.1 '.$error->getOAuth2Code());
    header('Content-Type: application/json;charset=UTF-8');
    header('Cache-Control: no-store');
    header('Pragma: no-cache');
    $res = array();
    $res['error'] = $error->getOAuth2Error();
    $desc = $error->getOAuth2ErrorDescription();
    if(!empty($desc)){
        $res['error_description'] = $desc;
    }
    echo json_encode($res);
    exit;
}

// build response
$res = array();
$res['user_id'] = $authInfo->userId;
$res['client_id'] = $authInfo->clientId;
$res['scope'] = $authInfo->scope;

header('HTTP/1.1 200 OK');
header('Content-Type: application/json;charset=UTF-8');
header('Cache-Control: no-store');
header('Pragma: no-cache');
echo json_encode($res);
