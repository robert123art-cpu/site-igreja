exports.onExecutePostLogin = async (event, api) => {
  api.idToken.setCustomClaim("role", "authenticated");

  const role = event.user.app_metadata?.siga_role === "admin" ? "admin" : "user";
  api.idToken.setCustomClaim(
    "https://github.com/robert123art-cpu/site-igreja/claims/siga_role",
    role,
  );
};
