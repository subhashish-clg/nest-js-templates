import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { JwtStrategy } from './strategies/jwt.strategy';
import { RefreshJwtStrategy } from './strategies/refresh.strategy';
import { GoogleAuthController } from './modules/google/google.controller';
import { GoogleAuthService } from './modules/google/google.service';
import { GoogleStrategy } from './strategies/google.strategy';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    PassportModule,
    JwtModule.register({}),
  ],
  providers: [
    AuthService,
    GoogleAuthService,
    JwtStrategy,
    RefreshJwtStrategy,
    GoogleStrategy,
  ],
  controllers: [AuthController, GoogleAuthController],
})
export class AuthModule {}
