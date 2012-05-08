<?php

require_once '../php-Akita_OAuth2/src/Akita/OAuth2/Server/Util.php';
require_once '../php-Akita_OAuth2/src/Akita/OAuth2/Server/AuthorizationHandler.php';
require_once '../php-Akita_OAuth2/src/Akita/OAuth2/Server/GrantHandlers.php';
require_once '../php-Akita_OAuth2/src/Akita/OAuth2/Server/ProtectedResource.php';
require_once '../php-Akita_OAuth2/src/Akita/OAuth2/Server/DataHandler.php';
require_once '../php-Akita_OAuth2/src/Akita/OAuth2/Server/Request.php';
require_once '../php-Akita_OAuth2/src/Akita/OAuth2/Model/AuthInfo.php';
require_once '../php-Akita_OAuth2/src/Akita/OAuth2/Model/AccessToken.php';
require_once './lib/DB.php';

class Akita_OAuth2_Server_Sample_DataHandler
    extends Akita_OAuth2_Server_DataHandler
{
    private $_request;
    private $_userId;
    private $_db;

    public function __construct($request){
        $this->_request = $request;
        $this->_db = new Akita_OAuth2_Server_Sample_DB();
    }

    public function setUserId($userId){
        $this->_userId = $userId;
    }

    /* abstruct functions */
    public function getRequest(){
        return $this->_request;
    }

    public function getUserId(){
        return $this->_userId;
    }

    public function getUserIdByCredentials( $username, $password ){
        if($username=='fakeuser@example.com' && $password=='fakepassword'){
            return $username;
        }else{
            return null;
        }
    }

    public function createOrUpdateAuthInfo( $params ){
        $authInfo = $this->_db->getAuthInfo($params['clientId'], $params['userId'], $params['scope']);
        if(is_null($authInfo)){
            $authId = hash_hmac('sha256','ai'.microtime(true).mt_rand(),$params['clientId'].$params['userId']);
            $authInfo = new Akita_OAuth2_Model_AuthInfo(
                                $authId,
                                $params['userId'],
                                $params['clientId'],
                                $params['scope']
            );
        }

        // optional member
        if(isset($this->_request->param['response_type'])){
            if(strpos($this->_request->param['response_type'],'code') !== false){
                $authInfo->code = hash_hmac('sha256','cd'.microtime(true).mt_rand(),$params['clientId'].$params['userId']);
                $authInfo->redirectUri = $this->_request->param['redirect_uri'];
            }
            //$authInfo->refreshToken = hash_hmac('sha256','rt'.microtime(true).mt_rand(),$params['clientId'].$params['userId']);
        }
        $exp = time() + 600;
        $this->_db->setAuthInfo($authInfo, $exp);
        return $authInfo;
    }

    public function createOrUpdateAccessToken( $params ){
        if(empty($scope)){
               $scope = $params['authInfo']->scope;
        }
        $expiresIn = 3600;
        $createdOn = time();
        $token = hash_hmac('sha256', 'at'.microtime(true).mt_rand(),$params['authInfo']->clientId.$params['authInfo']->userId);

        $accessToken = new Akita_OAuth2_Model_AccessToken(
                                                           $params['authInfo']->authId,
                                                           $token,
                                                           $scope,
                                                           $expiresIn,
                                                           $createdOn);

        $this->_db->setAccessToken($accessToken);
        return $accessToken;
    }

    public function getAuthInfoByCode( $code ){
        $authInfo = $this->_db->getAuthInfoByCode($code);
        if(!is_null($authInfo)){
            $exp = time() + 14*24*60*60;
            $this->_db->setAuthInfo($authInfo, $exp, 1);
        }
        return $authInfo;
    }

    public function getAuthInfoByRefreshToken( $refreshToken ){
        return $this->_db->getAuthInfoByRefreshToken($refreshToken);
    }

    public function getAccessToken( $token ){
        return $this->_db->getAccessTokenByToken($token);
    }

    public function getAuthInfoById( $authId ){
        return $this->_db->getAuthInfoByAuthId($authId);
    }

    public function validateClient( $clientId, $clientSecret, $grantType ){
        if($clientId=='cid00001' && $clientSecret=='csecret00001'){
            return true;
        }else{
            return false;
        }
    }

    public function validateClientById( $clientId ){
        if($clientId=='cid00001'){
            return true;
        }else{
            return false;
        }
    }

    public function validateUserById( $userId ){
        if($userId=='fakeuser@example.com'){
            return true;
        }else{
            return false;
        }
    }

    public function validateRedirectUri( $clientId, $redirectUri){
        
        $valid_redirectUri = 'http://'.$_SERVER['SERVER_NAME'].$_SERVER['SCRIPT_NAME'];
        if(strrpos($valid_redirectUri, '/Authorization.php') ){
            $valid_redirectUri = str_replace('Authorization.php','Client.php',$valid_redirectUri);
        }else{
            $valid_redirectUri = str_replace('Finish.php','Client.php',$valid_redirectUri);
        }

        if($clientId=='cid00001' && $redirectUri==$valid_redirectUri){
            return true;
        }else{
            return false;
        }
    }

    public function validateScope( $clientId, $scope ){
        if($clientId=='cid00001' && ($scope=='profile')){
            return true;
        }else{
            return false;
        }
    }

    public function validateScopeForTokenRefresh( $scope, $authInfo){
        if(strpos($authInfo->scope, $scope)!==false){
            return true;
        }else{
            return false;
        }
    }

    public function setRefreshToken( $authInfo ){
        $authInfo->code = "";
        $authInfo->refreshToken = hash_hmac('sha256','rt'.microtime(true).mt_rand(),$params['clientId'].$params['userId']);
        $exp = time() + 600;
        $this->_db->setAuthInfo($authInfo, $exp);
        return $authInfo;
    }
}
