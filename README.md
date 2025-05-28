# JWT_Authentication

This is a simple authenticated client-side rendered web application where users can log in and access protected content. The backend handles user authentication using manually created and validated JSON Web Tokens (JWTs) without third-party libraries. The project includes a RESTful API, secure cookie handling, and a basic frontend interface.

Components

Backend

* Built with Node.js and Express.
* REST API endpoints include:
    * User authentication and token issuance
    * Logout and token clearing
    * Retrieving the currently authenticated user from the JWT
* JWTs are manually created using the crypto and base64url libraries.
* JWTs are stored in secure HTTP-only cookies and include an exp claim and sanitized user data.
* Middleware validates the JWT’s signature and expiration before granting access to protected endpoints.
* Users are stored in a static users.json file and include salted and hashed passwords.

Frontend

* Fully client-side rendered.
* Pages include:
    * Login page for entering username and password
    * Home page displaying authenticated user details
* Unauthenticated users are redirected to the login page if they try to access protected routes.
* Includes a logout button to clear the session.
* Optional use of Bootstrap or another CSS framework for styling.

Deployment

Docker Setup

* Dockerfile: Builds the Node.js app for containerized deployment.
* docker-compose.yml: Adds a jwt service for the JWT app.
* default.conf.template: Proxies / and /jwt/ routes to the JWT container.

To Deploy Locally:

docker-compose build jwt  
docker-compose up

Usage:  
http://localhost/jwt/
