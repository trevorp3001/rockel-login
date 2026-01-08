module.exports = {
  apps: [
    {
      name: "rockel",
      script: "server.js",
      cwd: "/var/www/rockel-login",
      env_file: "/etc/rockel/production.env",
      time: true
    },
    {
      name: "rockel-staging",
      script: "server.js",
      cwd: "/var/www/rockel-login-staging",
      env_file: "/etc/rockel/staging.env",
      time: true
    }
  ]
};
