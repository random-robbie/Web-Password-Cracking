<?php
require('config.php');
if (!$email = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)) {
	die("Invalid Email");
}

if (strlen($_POST['password']) < 10) {
	die("Password too short!");
}

$password = $_POST['password'];


switch ($_POST['advisor']) {
	case "Site Owner":
		$managerEmail = $manager;
		break;
	default:
		die("Invalid Advisor");
}


$passwordSalt = substr(md5(rand()), 0, 8);
$passwordHash = hash("sha512", $passwordSalt . $password);

try {
	

	$query = $db->prepare("INSERT INTO users (email, hash, salt) VALUES (:email, :hash, :salt)");

	$query->bindParam(':email', $email);
	$query->bindParam(':hash', $passwordHash);
	$query->bindParam(':salt', $passwordSalt);
	$query->execute();

	$uid = $db->lastInsertId();

	$query = $db->prepare("INSERT INTO confirmation (uid, challenge, conType) VALUES (:uid, :challenge, :conType)");

	do {
		$emailConfirmChallenge = base64_encode(openssl_random_pseudo_bytes(48));
		$query->bindValue(":uid", $uid);
		$query->bindValue(":challenge", $emailConfirmChallenge);
		$query->bindValue(":conType", 'E');
	} while (!$query->execute());


//Manager confirmation challenge string
	do {
		$managerConfirmChallenge = base64_encode(openssl_random_pseudo_bytes(48));
		$query->bindValue(":uid", $uid); //TODO: is this needed?
		$query->bindValue(":challenge", $managerConfirmChallenge);
		$query->bindValue(":conType", 'M');
	} while (!$query->execute());

	

	$emailConfirmStr = $serverPrefix . $emailConfirmChallenge;
	mail($email,
		"DSU Cracking Email Confirmation",
		"Please go to the following link to confirm your account: " . $emailConfirmStr,
		"From: ".$from.""
	);

	$managerConfirmString = $serverPrefix . $managerConfirmChallenge;
	$managerMessage = "A user identified by $email has requested access to the password cracking box\r\n";
	$managerMessage .= "Go to the following link to confirm their request: $managerConfirmString";
	mail($managerEmail,
		"DSU Cracking User Confirmation",
		$managerMessage,
		"From: ".$from.""
	);

	$db = 0;

	echo "<script>alert('Your user has been created. When it is confirmed, you may access the system. Redirecting to home.'); window.location='/'; </script>";


} catch (PDOException $e) {
	error_log($e->getMessage());
}
