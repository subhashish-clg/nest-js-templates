import {
  Injectable,
  InternalServerErrorException,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { LoginDto, RegisterUserDto } from './dtos/user.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import * as argon2 from 'argon2';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  async register(body: RegisterUserDto) {
    const existingUser = await this.userRepository.findOne({
      where: {
        email: body.email,
      },
    });

    if (existingUser) {
      throw new UnauthorizedException('User with that email already exists');
    }

    try {
      const user = await this.userRepository.save(
        this.userRepository.create({
          ...body,
        }),
      );

      const { refreshToken, accessToken } = await this.generateTokens({
        sub: user.id,
        firstname: user.firstName,
        lastName: user.lastName,
        email: user.email,
      });

      await this.updateRefreshToken(user.id, refreshToken);

      return {
        id: user.id,
        accessToken,
        refreshToken,
      };
    } catch (error) {
      this.logger.error(error);
      throw new InternalServerErrorException('Something went wrong.');
    }
  }

  async login(body: LoginDto) {
    const user = await this.userRepository.findOne({
      where: {
        email: body.email,
      },
    });

    if (!user) {
      throw new UnauthorizedException('User does not exists');
    }

    const isValid = await bcrypt.compare(body.password, user.password);

    if (!isValid) throw new UnauthorizedException('Invalid email or password');

    try {
      const { refreshToken, accessToken } = await this.generateTokens({
        sub: user.id,
        firstname: user.firstName,
        lastName: user.lastName,
        email: user.email,
      });

      await this.updateRefreshToken(user.id, refreshToken);

      return {
        id: user.id,
        accessToken,
        refreshToken,
      };
    } catch (error) {
      this.logger.error(error);
      throw new InternalServerErrorException('Something went wrong.');
    }
  }

  async refreshToken(user: Partial<User>) {
    const { accessToken, refreshToken } = await this.generateTokens(user);
    await this.updateRefreshToken(user.id, refreshToken);

    return {
      id: user.id,
      accessToken,
      refreshToken,
    };
  }

  async validateUser(body: Partial<User>) {
    const user = await this.userRepository.findOne({
      where: {
        email: body.email,
      },
    });

    if (!user) throw new UnauthorizedException('Invalid token');

    return {
      id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
    };
  }

  async validateRefreshToken(userId: string, refreshToken: string) {
    const user = await this.userRepository.findOne({
      where: {
        id: userId,
      },
    });

    if (!user) throw new UnauthorizedException('Invalid refresh token.');

    const refreshTokenMatches = await argon2.verify(
      user.hashedRefreshToken,
      refreshToken,
    );

    if (!refreshTokenMatches)
      throw new UnauthorizedException('Invalid Refresh Token');

    return {
      id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
    };
  }

  /* Utils */
  async generateTokens(payload: object) {
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: this.configService.get('ACCESS_TOKEN_SECRET'),
        expiresIn: '15m',
      }),
      this.jwtService.signAsync(payload, {
        secret: this.configService.get('REFRESH_TOKEN_SECRET'),
        expiresIn: '15d',
      }),
    ]);

    return {
      accessToken,
      refreshToken,
    };
  }

  async updateRefreshToken(userId: string, refreshToken: string) {
    const hashedRefreshToken = await argon2.hash(refreshToken);

    return await this.userRepository.update(
      {
        id: userId,
      },
      { hashedRefreshToken },
    );
  }
}
