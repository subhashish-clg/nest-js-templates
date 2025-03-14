import { Controller, Get, Req, Res, UseGuards } from '@nestjs/common';
import { AuthService } from 'src/auth/auth.service';
import { GoogleAuthGuard } from 'src/auth/guards/google.guard';

@Controller('auth/google')
export class GoogleAuthController {
  constructor(private readonly authService: AuthService) {}

  @UseGuards(GoogleAuthGuard)
  @Get('/login')
  googleLogin() {}

  @UseGuards(GoogleAuthGuard)
  @Get('/callback')
  async googleCallback(@Req() req, @Res() res) {
    const user = req.user;

    const response = await this.authService.generateTokens({
      ...user,
    });

    res.redirect(`http://localhost:5173?token=${response.accessToken}`);
  }
}
