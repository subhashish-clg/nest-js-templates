import { LoginDto, RegisterUserDto } from './dtos/user.dto';
import { AuthService } from './auth.service';
import { Request } from 'express';
export declare class AuthController {
    private readonly authService;
    constructor(authService: AuthService);
    register(body: RegisterUserDto): Promise<{
        id: string;
        accessToken: string;
        refreshToken: string;
    }>;
    login(body: LoginDto): Promise<{
        id: string;
        accessToken: string;
        refreshToken: string;
    }>;
    refresh(req: Request): Promise<{
        id: string;
        accessToken: string;
        refreshToken: string;
    }>;
    profile(req: Request): Express.User;
}
