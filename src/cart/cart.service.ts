import { Injectable } from '@nestjs/common';

@Injectable()
export class CartService {
  private items = [];
  
  clearCart() {
    this.items = [];
    return { message: 'Cart cleared successfully', status: 200 };
  }
}