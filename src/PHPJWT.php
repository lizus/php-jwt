<?php
namespace Lizus\PHPJWT;

use \Firebase\JWT\JWT;
use \Firebase\JWT\Key;
use Symfony\Component\Uid\Uuid;

/**
 * 使用时，继承该类，然后填写三个属性值即可
 */
class PHPJWT
{
    protected static $key='';//用于jwt加密的key，尽量随机，该key是关键，不可告之任何人
    protected static $alg='';//jwt加密算法，https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-web-algorithms-40#section-3.1
    protected static $namespace='';//用于生成uuid的namespace，可用PHPJWT::generateNamespace()生成然后保存在该值中

    /**
     * jwt encode，传值必须要数组，只传需要的键值对，无须isa,aud
     */
    public static function encode($payload=[]){
        if(empty(static::$key) || empty(static::$alg)) return '';
        $payload['isa']=time();
        $payload['aud']=static::uuid();
        return JWT::encode($payload,static::$key,static::$alg);
    }

    /**
     * jwt decode，传值为jwt encode字符串，解码得到键值对数组或空数组
     */
    public static function decode($jwt){
        if(empty(static::$key) || empty(static::$alg)) return [];
        $decode=[];
        /**
         * jwt验证，如未通过，则直接返回空数组
         */
        try {
            $decode=JWT::decode($jwt,new Key(static::$key,static::$alg));
        } catch (\Throwable $th) {
            //错误处理
            return [];
        }
        try {
            $decode=json_decode(json_encode($decode),true);
        } catch (\Throwable $th) {
            //错误处理
            return [];
        }
        if(empty($decode)) return [];
        if(!is_array($decode) || !isset($decode['isa']) || !isset($decode['aud'])) return [];

        /**
         * 判断时间是否已过期
         */
        if(isset($decode['exp'])) {
            $now=time();
            $diff=$now-$decode['exp'];
            if($diff>=0) return [];
        }

        /**
         * 判断uuid是否是同一个
         */
        if($decode['aud']!=static::uuid()) return [];

        /**
         * 通过检查去掉timestamp和ip键再返回payload
         */
        unset($decode['isa']);
        unset($decode['aud']);
        return $decode;
    }

    /**
     * 用于生成namespace
     */
    public static function generateNamespace(){
        return Uuid::v4()->toRfc4122();
    }

    /**
     * 用于生成uuid
     */
    protected static function uuid(){
        if(empty(static::$namespace)) return ''; 
        $namespace = Uuid::fromRfc4122(static::$namespace);
        return Uuid::v5($namespace,static::get_ua().static::get_ip_address())->toBase58();
    }

    /**
     * 获得用户ua，如果不存在，则使用时间的md5值，这样的话，该jwt无法解码
     */
    protected static function get_ua(){
        if(\array_key_exists('HTTP_USER_AGENT',$_SERVER)){
            return $_SERVER['HTTP_USER_AGENT'];
        }
        return md5(time());
    }

    /**
     * 获得用户ip，如果不存在，则使用时间的md5值，这样的话，该jwt无法解码
     */
    protected static function get_ip_address(){
        foreach (array('HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR') as $key){
            if (array_key_exists($key, $_SERVER) === true){
                foreach (explode(',', $_SERVER[$key]) as $ip){
                    $ip = trim($ip); // just to be safe

                    if (filter_var($ip, FILTER_VALIDATE_IP)){
                        return $ip;
                    }
                }
            }
        }
        return md5(microtime());
    }
}
