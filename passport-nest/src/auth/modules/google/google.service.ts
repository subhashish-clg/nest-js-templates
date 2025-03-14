import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/auth/entities/user.entity';
import { Repository } from 'typeorm';

@Injectable()
export class GoogleAuthService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  async validateGoogleUser(googleUser: Partial<User>) {
    const user = await this.userRepository.findOne({
      where: { email: googleUser.email },
    });

    if (user) return user;
  }
}
