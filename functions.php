<?php

function crypto_rand_secure($min, $max){
  $range = $max - $min;
  if($range < 1) return $min;
  $log = ceil(log($range, 2));
  $bytes = (int)($log / 8) + 1;
  $bits = (int)$log + 1;
  $filter = (int) (1 << $bits) - 1;
  do {
      $rnd = hexdec(bin2hex(openssl_random_pseudo_bytes($bytes)));
      $rnd = $rnd & $filter;
  }while($rnd > $range);
  return $min + $rnd;
}
function getToken($lengh){
  $token = "";
  $codeAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  $codeAlphabet .= "abcdefghijklmnopqrstuvwxyz";
  $codeAlphabet .= "0123456789";
  $max = strlen($codeAlphabet);
  for($i=0; $i < $lengh; $i++){
      $token .= $codeAlphabet[crypto_rand_secure(0, $max-1)];
  }
  return $token;
}

function form_token($token){
    if (!(isset($token)) OR !(isset($_SESSION['csrf_token'])) OR ($token != $_SESSION['csrf_token'])){
        return false;
    }else{
        return true;
    }
}

function normalize($key, $url, $error){
    if($key === 'error' OR $key === null OR !isset($key)){
      ?><script type="text/javascript">
      window.location="<?php echo $url; ?>";
      </script><?php
        $_SESSION['message'] = $error;
      die();
    }else{
      return trim($key);
    }
}


?>
