"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var AuthService_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthService = void 0;
const common_1 = require("@nestjs/common");
const typeorm_1 = require("@nestjs/typeorm");
const user_entity_1 = require("./entities/user.entity");
const typeorm_2 = require("typeorm");
const jwt_1 = require("@nestjs/jwt");
const config_1 = require("@nestjs/config");
const bcrypt = require("bcrypt");
const argon2 = require("argon2");
let AuthService = AuthService_1 = class AuthService {
    constructor(jwtService, configService, userRepository) {
        this.jwtService = jwtService;
        this.configService = configService;
        this.userRepository = userRepository;
        this.logger = new common_1.Logger(AuthService_1.name);
    }
    async register(body) {
        const existingUser = await this.userRepository.findOne({
            where: {
                email: body.email,
            },
        });
        if (existingUser) {
            throw new common_1.UnauthorizedException('User with that email already exists');
        }
        try {
            const user = await this.userRepository.save(this.userRepository.create({
                ...body,
            }));
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
        }
        catch (error) {
            this.logger.error(error);
            throw new common_1.InternalServerErrorException('Something went wrong.');
        }
    }
    async login(body) {
        const user = await this.userRepository.findOne({
            where: {
                email: body.email,
            },
        });
        if (!user) {
            throw new common_1.UnauthorizedException('User does not exists');
        }
        const isValid = await bcrypt.compare(body.password, user.password);
        if (!isValid)
            throw new common_1.UnauthorizedException('Invalid email or password');
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
        }
        catch (error) {
            this.logger.error(error);
            throw new common_1.InternalServerErrorException('Something went wrong.');
        }
    }
    async refreshToken(user) {
        const { accessToken, refreshToken } = await this.generateTokens(user);
        await this.updateRefreshToken(user.id, refreshToken);
        return {
            id: user.id,
            accessToken,
            refreshToken,
        };
    }
    async validateUser(body) {
        const user = await this.userRepository.findOne({
            where: {
                email: body.email,
            },
        });
        if (!user)
            throw new common_1.UnauthorizedException('Invalid token');
        return {
            id: user.id,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
        };
    }
    async validateRefreshToken(userId, refreshToken) {
        const user = await this.userRepository.findOne({
            where: {
                id: userId,
            },
        });
        if (!user)
            throw new common_1.UnauthorizedException('Invalid refresh token.');
        const refreshTokenMatches = await argon2.verify(user.hashedRefreshToken, refreshToken);
        if (!refreshTokenMatches)
            throw new common_1.UnauthorizedException('Invalid Refresh Token');
        return {
            id: user.id,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
        };
    }
    async generateTokens(payload) {
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
    async updateRefreshToken(userId, refreshToken) {
        const hashedRefreshToken = await argon2.hash(refreshToken);
        return await this.userRepository.update({
            id: userId,
        }, { hashedRefreshToken });
    }
};
exports.AuthService = AuthService;
exports.AuthService = AuthService = AuthService_1 = __decorate([
    (0, common_1.Injectable)(),
    __param(2, (0, typeorm_1.InjectRepository)(user_entity_1.User)),
    __metadata("design:paramtypes", [jwt_1.JwtService,
        config_1.ConfigService,
        typeorm_2.Repository])
], AuthService);
//# sourceMappingURL=auth.service.js.map