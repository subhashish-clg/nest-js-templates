import { LoginDto, RegisterUserDto } from './dtos/user.dto';
import { User } from './entities/user.entity';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
export declare class AuthService {
    private readonly jwtService;
    private readonly configService;
    private readonly userRepository;
    private readonly logger;
    constructor(jwtService: JwtService, configService: ConfigService, userRepository: Repository<User>);
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
    refreshToken(user: Partial<User>): Promise<{
        id: string;
        accessToken: string;
        refreshToken: string;
    }>;
    validateUser(body: Partial<User>): Promise<{
        id: string;
        firstName: string;
        lastName: string;
        email: string;
    }>;
    validateRefreshToken(userId: string, refreshToken: string): Promise<{
        id: string;
        firstName: string;
        lastName: string;
        email: string;
    }>;
    generateTokens(payload: object): Promise<{
        accessToken: string;
        refreshToken: string;
    }>;
    updateRefreshToken(userId: string, refreshToken: string): Promise<import("typeorm").UpdateResult>;
}
