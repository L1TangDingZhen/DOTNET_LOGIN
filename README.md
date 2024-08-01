# JWT-Based Authentication System

This project demonstrates a basic implementation of a JWT (JSON Web Token) based authentication system using ASP.NET Core.

## Features

- User Registration
- User Login
- Token-based Authentication
- Secured Endpoints with Authorization
- Password Hashing

## Technologies Used

- ASP.NET Core
- Entity Framework Core
- JWT (JSON Web Token)
- MySQL (or any other supported database)
- Swagger (for API documentation)

## Getting Started

### Prerequisites

- .NET SDK
- MySQL Server (or any other supported database)
- Visual Studio or any other C# IDE


## File Structure
- Program.cs - Configures services and middleware, including JWT authentication.
- appsettings.json - Contains application settings and database connection strings.
- Controllers/AccountController.cs - Handles user registration, login, and other user-related operations.
- Services/JwtService.cs - Generates JWT tokens.
- Models/User.cs - Represents the user entity.
- Models/LoginRequest.cs - Represents the login request model.
- DbContext/ApplicationDbContext.cs - Configures the database context.
