import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException, Payload } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import { LoginUserDto, RegisterUserDto } from './dto';
import * as bcrypt from 'bcrypt'
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interfaces';
import { envs } from 'src/config';


@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit{

  private readonly logger = new Logger('AuthService')

  constructor(
    private readonly jwtService: JwtService // Inyección del jwtService
  ){
    super();
  }

  onModuleInit() {
    this.$connect()
    this.logger.log('MongoDB connected')
  }


  async signJWT(payload: JwtPayload){                                   // Genera un jwt en base a un payload
    return this.jwtService.sign(payload)
  }

  async verifyToken(token:string){
    try {
      
      const { sub, iat, exp, ...user } = this.jwtService.verify(token, { // Verificamos la info del token con el secret y nos quedamos solo con el user
        secret: envs.jwtSecret
      })

      return{
        user: user,
        token: await this.signJWT(user)                                   // Revalidamos el token con la info del user
      }


    } catch (error) {
      console.log(error);
      throw new RpcException({
        status: 401,
        message: 'Invalid token'
      })
    }
  }

  async registerUser(registerUserDto: RegisterUserDto){
    try {

      const { email, name, password } = registerUserDto
      
      const user = await this.user.findUnique({
        where: { email }
      })

      if(user) {
        throw new RpcException({
          status: 400,
          message: 'User already exists'
        })
      }

      const newUser = await this.user.create({
        data: {
          email: email,
          password: bcrypt.hashSync(password, 10),
          name: name
        }
      });

      const { password: __, ...rest} = newUser

      return {
        user: rest,
        token: await this.signJWT(rest)
      }

      
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message
      })
    }
  }

  async loginUser(loginUserDto: LoginUserDto) {
    
    try {

      const { email, password } = loginUserDto;

      const user = await this.user.findUnique({
        where: { email }
      })

      if (!user) {
        throw new RpcException({
          status: 400,
          message: 'User/Password not valid'
        })
      }

      const isPasswordValid = bcrypt.compareSync(password, user.password)

      if(!isPasswordValid){
        throw new RpcException({
          status: 400,
          message: "User/Password not valid"
        })
      }

      const { password: __, ...rest} = user;

      return {
        user: rest,
        token: await this.signJWT(rest)
      }

    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message
      })
    }
  }
}
