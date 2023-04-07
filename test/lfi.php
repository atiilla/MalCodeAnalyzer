<?php 

$paths = scandir('/html');

$file  = isset($_GET['display']) ? $_GET['display'] : false;

if(!$file) 
{
 die('no display provided');
}

$html = '';

foreach($paths as $path) {

   if($path !== '.' && $path !== '..' && $path === $file.'.html') {
     $html = file_get_contents($path);
   }
  
}


echo $html;

?>