import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { envs } from 'src/config';

@Module({
  controllers: [AuthController],          // Controlador para manejar las peticiones http relacionadas con la autenticación
  providers: [AuthService],               // Servicio para la lógica de negocio de autenticación.
  imports: [                              // Importación del modulo jwt
    JwtModule.register({  
      global: true,                       // Accesible globalmente
      secret: envs.jwtSecret,             // Clave secreta utilizada para firmar los tokens 
      signOptions: { expiresIn: '2h' },   // Expiración en 2 horas
    }),
  ]
})
export class AuthModule {}
