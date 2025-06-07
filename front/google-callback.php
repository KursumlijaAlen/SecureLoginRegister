<?php require '../config_default.php'; ?>
<!DOCTYPE html>
<html><body>
<script>
(async ()=>{
  const params = new URLSearchParams(window.location.search);
  const code   = params.get('code');
  if (!code) {
    alert('No code from Google');
    return window.location='login.php';
  }

  const res  = await fetch(`../api/google-callback?code=${code}`);
  const body = await res.json();

  if (!res.ok) {
    alert(body.error||'Google SSO error');
    return window.location='login.php';
  }

  if (body.requires_2fa) {
    // hand off to your existing OTP screen
    localStorage.removeItem('auth_token');
    window.location = 'login.php?showOtp=1';
  } else {
    // full login
    localStorage.setItem('auth_token', body.token);
    window.location = 'dashboard.php';
  }
})();
</script>
</body></html>
