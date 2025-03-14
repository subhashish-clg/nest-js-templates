import { Body, Controller, Get, Post, Req, UseGuards } from '@nestjs/common';
import { LoginDto, RegisterUserDto } from './dtos/user.dto';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt.guard';
import { Request } from 'express';
import { RefreshJwtGuard } from './guards/refresh.guard';
import { User } from './entities/user.entity';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/register')
  register(@Body() body: RegisterUserDto) {
    return this.authService.register(body);
  }

  @Post('/login')
  login(@Body() body: LoginDto) {
    return this.authService.login(body);
  }

  @UseGuards(RefreshJwtGuard)
  @Post('/refresh')
  refresh(@Req() req: Request) {
    return this.authService.refreshToken(req.user as Partial<User>);
  }

  @UseGuards(JwtAuthGuard)
  @Get('/profile')
  profile(@Req() req: Request) {
    return req.user;
  }
}
